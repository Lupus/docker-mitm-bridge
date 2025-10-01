.PHONY: help build push deploy clean test logs status delete redeploy

NAMESPACE ?= kyverno-intercept
IMAGE ?= ghcr.io/lupus/docker-mitm-bridge/sds-service:latest

help: ## Show this help message
	@echo "SDS Service - Make targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker image
	docker build -t $(IMAGE) .

push: ## Push Docker image to registry
	docker push $(IMAGE)

build-push: build push ## Build and push Docker image

deploy: ## Deploy to Kubernetes
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f k8s/

clean: ## Remove built artifacts
	rm -f sds-service sds-service.gz sds-service-part-*
	docker rmi $(IMAGE) || true

test: ## Deploy test pod
	kubectl apply -f k8s/test-pod.yaml

logs: ## Show SDS service logs
	kubectl logs -n $(NAMESPACE) -l app=sds-service -f

status: ## Show deployment status
	@echo "=== SDS Service Status ==="
	kubectl get pods -n $(NAMESPACE) -l app=sds-service
	@echo ""
	@echo "=== Service Endpoints ==="
	kubectl get svc -n $(NAMESPACE) sds-service
	@echo ""
	@echo "=== Recent Events ==="
	kubectl get events -n $(NAMESPACE) --field-selector involvedObject.kind=Pod --sort-by='.lastTimestamp' | grep sds-service | tail -n 10

delete: ## Delete SDS service from cluster
	kubectl delete -f k8s/deployment.yaml -f k8s/service.yaml || true

redeploy: build-push delete deploy ## Full rebuild and redeploy

restart: ## Restart deployment
	kubectl rollout restart deployment/sds-service -n $(NAMESPACE)
	kubectl rollout status deployment/sds-service -n $(NAMESPACE)