build:
	go build -o bin/cvelint cmd/cvelint/main.go

clean:
	/bin/rm -f bin/cvelint

release:
	@LATEST=$$(git tag --sort=-v:refname | head -1); \
	MAJOR=$$(echo "$$LATEST" | cut -d. -f1); \
	MINOR=$$(echo "$$LATEST" | cut -d. -f2); \
	PATCH=$$(echo "$$LATEST" | cut -d. -f3); \
	NEXT="$$MAJOR.$$((MINOR + 1)).0"; \
	if [ -z "$(VERSION)" ]; then \
		printf "Next version [$$NEXT]: "; \
		read INPUT; \
		VERSION=$${INPUT:-$$NEXT}; \
	else \
		VERSION="$(VERSION)"; \
	fi; \
	if ! echo "$$VERSION" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: VERSION must match vMAJOR.MINOR.PATCH (e.g. $$NEXT)"; \
		exit 1; \
	fi; \
	if git tag -l "$$VERSION" | grep -q "$$VERSION"; then \
		echo "ERROR: tag $$VERSION already exists"; \
		exit 1; \
	fi; \
	echo "Releasing $$VERSION..."; \
	git tag $$VERSION && \
	git push origin $$VERSION && \
	GITHUB_TOKEN=$$(gh auth token) goreleaser release --clean
