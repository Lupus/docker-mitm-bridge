package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dynamic_forward_proxy_cluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dynamic_forward_proxy_common "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dynamic_forward_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	tls_inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpproto "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type CertificateAuthority struct {
	cert      *x509.Certificate
	key       *rsa.PrivateKey
	certPEM   []byte
	keyPEM    []byte
	mu        sync.RWMutex
	certCache map[string]*CertificatePair
}

type CertificatePair struct {
	certPEM []byte
	keyPEM  []byte
}

// OPA response structure for required_domains query
type OPARequiredDomainsResponse struct {
	Result []string `json:"result"`
}

// Load CA from mounted Secret
func LoadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	log.Printf("Loading CA from %s and %s", certPath, keyPath)

	// Read certificate
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	// Read private key
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		keyInterface, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA private key is not RSA")
		}
	}

	ca := &CertificateAuthority{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		certCache: make(map[string]*CertificatePair),
	}

	log.Println("CA loaded successfully")
	return ca, nil
}

func (ca *CertificateAuthority) GenerateCertificate(domain string) (*CertificatePair, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Check cache
	if cached, ok := ca.certCache[domain]; ok {
		log.Printf("Returning cached certificate for domain: %s", domain)
		return cached, nil
	}

	log.Printf("Generating new certificate for domain: %s", domain)

	// Generate private key for the domain
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pair := &CertificatePair{
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}

	// Cache the certificate
	ca.certCache[domain] = pair

	log.Printf("Certificate generated for domain: %s", domain)
	return pair, nil
}

func (ca *CertificateAuthority) GetCAPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPEM
}

// Query OPA for required domains
func QueryOPADomains(opaURL string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/data/intercept/required_domains", opaURL)
	log.Printf("Querying OPA for required domains: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(body))
	}

	var opaResp OPARequiredDomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	log.Printf("OPA returned %d domains", len(opaResp.Result))
	return opaResp.Result, nil
}

// Wait for OPA to be ready
func WaitForOPA(opaURL string, timeout time.Duration) error {
	healthURL := fmt.Sprintf("%s/health", opaURL)
	log.Printf("Waiting for OPA to be ready: %s", healthURL)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			log.Println("OPA is ready")
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for OPA")
}

type SDSServer struct {
	ca      *CertificateAuthority
	version int
	mu      sync.Mutex
}

func NewSDSServer(ca *CertificateAuthority) *SDSServer {
	return &SDSServer{
		ca:      ca,
		version: 0,
	}
}

func (s *SDSServer) StreamSecrets(stream secret.SecretDiscoveryService_StreamSecretsServer) error {
	log.Println("Client connected to StreamSecrets")

	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Stream error: %v", err)
			return err
		}

		log.Printf("Received SDS request: %+v", req)

		resources := make([]*anypb.Any, 0)

		// Process each requested resource
		for _, resourceName := range req.ResourceNames {
			log.Printf("Requested resource: %s", resourceName)

			// Generate certificate for the requested domain
			pair, err := s.ca.GenerateCertificate(resourceName)
			if err != nil {
				log.Printf("Failed to generate certificate for %s: %v", resourceName, err)
				continue
			}

			// Create TLS certificate secret
			tlsCert := &tlsv3.Secret{
				Name: resourceName,
				Type: &tlsv3.Secret_TlsCertificate{
					TlsCertificate: &tlsv3.TlsCertificate{
						CertificateChain: &core.DataSource{
							Specifier: &core.DataSource_InlineBytes{
								InlineBytes: pair.certPEM,
							},
						},
						PrivateKey: &core.DataSource{
							Specifier: &core.DataSource_InlineBytes{
								InlineBytes: pair.keyPEM,
							},
						},
					},
				},
			}

			// Marshal to Any
			anySecret, err := anypb.New(tlsCert)
			if err != nil {
				log.Printf("Failed to marshal secret: %v", err)
				continue
			}

			resources = append(resources, anySecret)
		}

		// Send response
		s.mu.Lock()
		resp := &discovery.DiscoveryResponse{
			VersionInfo: fmt.Sprintf("%d", s.version),
			Resources:   resources,
			TypeUrl:     resource.SecretType,
			Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		s.version++
		s.mu.Unlock()

		if err := stream.Send(resp); err != nil {
			log.Printf("Failed to send response: %v", err)
			return err
		}

		log.Printf("Sent %d certificates", len(resources))
	}
}

func (s *SDSServer) DeltaSecrets(secret.SecretDiscoveryService_DeltaSecretsServer) error {
	return fmt.Errorf("DeltaSecrets not implemented")
}

func (s *SDSServer) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	log.Printf("FetchSecrets called with request: %+v", req)

	resources := make([]*anypb.Any, 0)

	for _, resourceName := range req.ResourceNames {
		log.Printf("Fetching resource: %s", resourceName)

		// Generate certificate for the requested domain
		pair, err := s.ca.GenerateCertificate(resourceName)
		if err != nil {
			log.Printf("Failed to generate certificate for %s: %v", resourceName, err)
			continue
		}

		// Create TLS certificate secret
		tlsCert := &tlsv3.Secret{
			Name: resourceName,
			Type: &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: pair.certPEM,
						},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: pair.keyPEM,
						},
					},
				},
			},
		}

		// Marshal to Any
		anySecret, err := anypb.New(tlsCert)
		if err != nil {
			log.Printf("Failed to marshal secret: %v", err)
			continue
		}

		resources = append(resources, anySecret)
		log.Printf("Added certificate for resource: %s", resourceName)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := &discovery.DiscoveryResponse{
		VersionInfo: fmt.Sprintf("%d", s.version),
		Resources:   resources,
		TypeUrl:     resource.SecretType,
		Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	s.version++
	return resp, nil
}

type LDSServer struct {
	domains       []string
	listenerCache []*anypb.Any
	version       int
	mu            sync.RWMutex
}

func NewLDSServer(domains []string) (*LDSServer, error) {
	server := &LDSServer{
		domains: domains,
		version: 1,
	}

	if err := server.buildListener(); err != nil {
		return nil, err
	}

	return server, nil
}

func (s *LDSServer) buildListener() error {
	log.Println("Building Envoy listener configuration...")

	// Build filter chains for each domain
	filterChains := make([]*listener.FilterChain, 0, len(s.domains)+1)

	// Create HTTP Connection Manager configuration
	for _, domain := range s.domains {
		log.Printf("Adding filter chain for domain: %s", domain)

		// Create ext_authz filter
		extAuthzConfig := &ext_authz.ExtAuthz{
			Services: &ext_authz.ExtAuthz_GrpcService{
				GrpcService: &core.GrpcService{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
							ClusterName: "ext_authz_cluster",
						},
					},
					Timeout: durationpb.New(10 * time.Second),
				},
			},
			TransportApiVersion: core.ApiVersion_V3,
		}

		extAuthzAny, err := anypb.New(extAuthzConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal ext_authz config: %w", err)
		}

		// Create router filter
		routerConfig := &router.Router{}
		routerAny, err := anypb.New(routerConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal router config: %w", err)
		}

		// Create HTTP Connection Manager
		manager := &hcm.HttpConnectionManager{
			CodecType:  hcm.HttpConnectionManager_AUTO,
			StatPrefix: fmt.Sprintf("ingress_http_%s", sanitizeDomain(domain)),
			RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
				RouteConfig: &route.RouteConfiguration{
					Name: fmt.Sprintf("local_route_%s", sanitizeDomain(domain)),
					VirtualHosts: []*route.VirtualHost{
						{
							Name:    domain,
							Domains: []string{domain},
							Routes: []*route.Route{
								{
									Match: &route.RouteMatch{
										PathSpecifier: &route.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: &route.Route_Route{
										Route: &route.RouteAction{
											ClusterSpecifier: &route.RouteAction_Cluster{
												Cluster: "dynamic_forward_proxy_cluster",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			HttpFilters: []*hcm.HttpFilter{
				{
					Name: "envoy.filters.http.ext_authz",
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: extAuthzAny,
					},
				},
				{
					Name: "envoy.filters.http.dynamic_forward_proxy",
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: func() *anypb.Any {
							dfpFilterConfig := &dynamic_forward_proxy.FilterConfig{
								ImplementationSpecifier: &dynamic_forward_proxy.FilterConfig_DnsCacheConfig{
									DnsCacheConfig: &dynamic_forward_proxy_common.DnsCacheConfig{
										Name:            "dynamic_forward_proxy_cache_config",
										DnsLookupFamily: cluster.Cluster_V4_ONLY,
										MaxHosts:        wrapperspb.UInt32(100),
									},
								},
							}
							any, _ := anypb.New(dfpFilterConfig)
							return any
						}(),
					},
				},
				{
					Name: "envoy.filters.http.router",
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: routerAny,
					},
				},
			},
		}

		managerAny, err := anypb.New(manager)
		if err != nil {
			return fmt.Errorf("failed to marshal http connection manager: %w", err)
		}

		// Create downstream TLS context
		downstreamTLS := &tlsv3.DownstreamTlsContext{
			CommonTlsContext: &tlsv3.CommonTlsContext{
				TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
					{
						Name: domain,
						SdsConfig: &core.ConfigSource{
							ResourceApiVersion: core.ApiVersion_V3,
							ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
								ApiConfigSource: &core.ApiConfigSource{
									ApiType:             core.ApiConfigSource_GRPC,
									TransportApiVersion: core.ApiVersion_V3,
									GrpcServices: []*core.GrpcService{
										{
											TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
												EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
													ClusterName: "xds_cluster",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		downstreamTLSAny, err := anypb.New(downstreamTLS)
		if err != nil {
			return fmt.Errorf("failed to marshal downstream TLS context: %w", err)
		}

		// Create filter chain with SNI matching
		filterChain := &listener.FilterChain{
			FilterChainMatch: &listener.FilterChainMatch{
				ServerNames: []string{domain},
			},
			Filters: []*listener.Filter{
				{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: managerAny,
					},
				},
			},
			TransportSocket: &core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: downstreamTLSAny,
				},
			},
		}

		filterChains = append(filterChains, filterChain)
	}

	// Create TLS inspector listener filter to extract SNI
	tlsInspectorConfig := &tls_inspector.TlsInspector{}
	tlsInspectorAny, err := anypb.New(tlsInspectorConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal tls inspector: %w", err)
	}

	// Create the listener
	lis := &listener.Listener{
		Name: "listener_0",
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 15001,
					},
				},
			},
		},
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: tlsInspectorAny,
				},
			},
		},
		FilterChains: filterChains,
	}

	lisAny, err := anypb.New(lis)
	if err != nil {
		return fmt.Errorf("failed to marshal listener: %w", err)
	}

	s.listenerCache = []*anypb.Any{lisAny}

	log.Printf("Listener configuration built with %d filter chains", len(filterChains))
	return nil
}

func sanitizeDomain(domain string) string {
	// Simple sanitization for use in names
	result := ""
	for _, c := range domain {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result += string(c)
		} else {
			result += "_"
		}
	}
	return result
}

func (s *LDSServer) StreamListeners(stream listenerservice.ListenerDiscoveryService_StreamListenersServer) error {
	log.Println("Client connected to StreamListeners")

	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Stream error: %v", err)
			return err
		}

		log.Printf("Received LDS request: %+v", req)

		s.mu.RLock()
		resp := &discovery.DiscoveryResponse{
			VersionInfo: fmt.Sprintf("%d", s.version),
			Resources:   s.listenerCache,
			TypeUrl:     resource.ListenerType,
			Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		s.mu.RUnlock()

		if err := stream.Send(resp); err != nil {
			log.Printf("Failed to send response: %v", err)
			return err
		}

		log.Println("Sent listener configuration")
	}
}

func (s *LDSServer) DeltaListeners(listenerservice.ListenerDiscoveryService_DeltaListenersServer) error {
	return fmt.Errorf("DeltaListeners not implemented")
}

func (s *LDSServer) FetchListeners(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	log.Printf("FetchListeners called with request: %+v", req)

	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := &discovery.DiscoveryResponse{
		VersionInfo: fmt.Sprintf("%d", s.version),
		Resources:   s.listenerCache,
		TypeUrl:     resource.ListenerType,
		Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	return resp, nil
}

type CDSServer struct {
	clusterCache []*anypb.Any
	version      int
	mu           sync.RWMutex
	opaGrpcPort  string
}

func NewCDSServer(opaGrpcPort string) (*CDSServer, error) {
	server := &CDSServer{
		version:     1,
		opaGrpcPort: opaGrpcPort,
	}

	if err := server.buildClusters(); err != nil {
		return nil, err
	}

	return server, nil
}

func (s *CDSServer) buildClusters() error {
	log.Println("Building Envoy cluster configuration...")

	clusters := make([]*anypb.Any, 0)

	// 1. ext_authz_cluster - gRPC cluster for OPA authorization
	// Parse OPA gRPC port
	opaPort := uint32(15021)
	if s.opaGrpcPort != "" {
		var port int
		if _, err := fmt.Sscanf(s.opaGrpcPort, "%d", &port); err == nil {
			opaPort = uint32(port)
		}
	}

	extAuthzCluster := &cluster.Cluster{
		Name:           "ext_authz_cluster",
		ConnectTimeout: durationpb.New(1 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_STATIC,
		},
		LbPolicy: cluster.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "ext_authz_cluster",
			Endpoints: []*endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Protocol: core.SocketAddress_TCP,
												Address:  "127.0.0.1",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: opaPort,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Add HTTP/2 protocol options for gRPC
	httpProtocolOpts := &httpproto.HttpProtocolOptions{
		UpstreamProtocolOptions: &httpproto.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &httpproto.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &httpproto.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
			},
		},
	}
	httpProtocolOptsAny, _ := anypb.New(httpProtocolOpts)

	extAuthzCluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpProtocolOptsAny,
	}

	extAuthzAny, err := anypb.New(extAuthzCluster)
	if err != nil {
		return fmt.Errorf("failed to marshal ext_authz_cluster: %w", err)
	}
	clusters = append(clusters, extAuthzAny)

	// 2. dynamic_forward_proxy_cluster - for upstream connections
	dynamicForwardProxyCluster := &cluster.Cluster{
		Name:           "dynamic_forward_proxy_cluster",
		ConnectTimeout: durationpb.New(10 * time.Second),
		LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
		ClusterDiscoveryType: &cluster.Cluster_ClusterType{
			ClusterType: &cluster.Cluster_CustomClusterType{
				Name: "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: func() *anypb.Any {
					// Properly wrap DnsCacheConfig in ClusterConfig
					dfpClusterConfig := &dynamic_forward_proxy_cluster.ClusterConfig{
						ClusterImplementationSpecifier: &dynamic_forward_proxy_cluster.ClusterConfig_DnsCacheConfig{
							DnsCacheConfig: &dynamic_forward_proxy_common.DnsCacheConfig{
								Name:            "dynamic_forward_proxy_cache_config",
								DnsLookupFamily: cluster.Cluster_V4_ONLY,
								MaxHosts:        wrapperspb.UInt32(100),
							},
						},
					}
					any, _ := anypb.New(dfpClusterConfig)
					return any
				}(),
			},
		},
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: func() *anypb.Any {
					upstreamTLS := &tlsv3.UpstreamTlsContext{
						Sni: "{sni}",
						CommonTlsContext: &tlsv3.CommonTlsContext{
							ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
								ValidationContext: &tlsv3.CertificateValidationContext{
									TrustedCa: &core.DataSource{
										Specifier: &core.DataSource_Filename{
											Filename: "/etc/ssl/certs/ca-certificates.crt",
										},
									},
								},
							},
						},
					}
					any, _ := anypb.New(upstreamTLS)
					return any
				}(),
			},
		},
	}

	dynamicForwardProxyAny, err := anypb.New(dynamicForwardProxyCluster)
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic_forward_proxy_cluster: %w", err)
	}
	clusters = append(clusters, dynamicForwardProxyAny)

	s.clusterCache = clusters
	log.Printf("Cluster configuration built with %d clusters", len(clusters))
	return nil
}

func (s *CDSServer) StreamClusters(stream clusterservice.ClusterDiscoveryService_StreamClustersServer) error {
	log.Println("Client connected to StreamClusters")

	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Stream error: %v", err)
			return err
		}

		log.Printf("Received CDS request: %+v", req)

		s.mu.RLock()
		resp := &discovery.DiscoveryResponse{
			VersionInfo: fmt.Sprintf("%d", s.version),
			Resources:   s.clusterCache,
			TypeUrl:     resource.ClusterType,
			Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		s.mu.RUnlock()

		if err := stream.Send(resp); err != nil {
			log.Printf("Failed to send response: %v", err)
			return err
		}

		log.Println("Sent cluster configuration")
	}
}

func (s *CDSServer) DeltaClusters(clusterservice.ClusterDiscoveryService_DeltaClustersServer) error {
	return fmt.Errorf("DeltaClusters not implemented")
}

func (s *CDSServer) FetchClusters(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	log.Printf("FetchClusters called with request: %+v", req)

	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := &discovery.DiscoveryResponse{
		VersionInfo: fmt.Sprintf("%d", s.version),
		Resources:   s.clusterCache,
		TypeUrl:     resource.ClusterType,
		Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	return resp, nil
}

func main() {
	log.Println("Starting xDS Control Plane (CDS+LDS+SDS)...")

	// Get configuration from environment
	grpcPort := os.Getenv("SDS_GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "15080"
	}

	httpPort := os.Getenv("SDS_HTTP_PORT")
	if httpPort == "" {
		httpPort = "15081"
	}

	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		opaURL = "http://localhost:15020"
	}

	opaGrpcPort := os.Getenv("OPA_GRPC_PORT")
	if opaGrpcPort == "" {
		opaGrpcPort = "15021"
	}

	caCertPath := os.Getenv("CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = "/ca-secret/tls.crt"
	}

	caKeyPath := os.Getenv("CA_KEY_PATH")
	if caKeyPath == "" {
		caKeyPath = "/ca-secret/tls.key"
	}

	// Load CA from mounted Secret
	ca, err := LoadCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}

	// Wait for OPA to be ready
	if err := WaitForOPA(opaURL, 60*time.Second); err != nil {
		log.Fatalf("Failed to wait for OPA: %v", err)
	}

	// Query OPA for required domains
	domains, err := QueryOPADomains(opaURL)
	if err != nil {
		log.Fatalf("Failed to query OPA for domains: %v", err)
	}

	if len(domains) == 0 {
		log.Println("Warning: No domains configured in OPA policy")
	}

	log.Printf("Pre-generating certificates for %d domains...", len(domains))

	// Pre-generate certificates for all required domains
	for _, domain := range domains {
		if _, err := ca.GenerateCertificate(domain); err != nil {
			log.Printf("Warning: Failed to pre-generate certificate for %s: %v", domain, err)
		}
	}

	log.Println("Certificate pre-generation completed")

	// Create SDS server
	sdsServer := NewSDSServer(ca)

	// Create LDS server
	ldsServer, err := NewLDSServer(domains)
	if err != nil {
		log.Fatalf("Failed to create LDS server: %v", err)
	}

	// Create CDS server
	cdsServer, err := NewCDSServer(opaGrpcPort)
	if err != nil {
		log.Fatalf("Failed to create CDS server: %v", err)
	}

	// Start HTTP server for health checks
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	go func() {
		log.Printf("HTTP server listening on port %s", httpPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%s", httpPort), nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Create gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	secret.RegisterSecretDiscoveryServiceServer(grpcServer, sdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, ldsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, cdsServer)

	// Start gRPC listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", grpcPort))
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port: %v", err)
	}

	log.Printf("gRPC xDS Control Plane (CDS+LDS+SDS) listening on port %s", grpcPort)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}
