.PHONY: help all deps_get deps_update deps_tidy gofmt lint_clean lint_run \
test test_clean test_coverage test_race

NULL :=
GO_FMT_DIRS := ./pkg/
LINT_DIRS := ./pkg/...
TEST_DIRS := ./pkg/...

# all runs help
all : help

# help lists out targets
help :
	$(info $(NULL))
	$(info ** Available Targets **)
	$(info $(NULL))
	$(info $(NULL)	deps_get		- download the dependencies for this project to the vendor folder)
	$(info $(NULL)	deps_tidy		- remove old and duplicate dependencies from go.sum)
	$(info $(NULL)	deps_update		- update the dependencies for this project)
	$(info $(NULL)	gofmt			- runs gofmt, formatting all project source files)
	$(info $(NULL)	lint_clean		- cleans the lint tools cache)
	$(info $(NULL)	lint_run		- runs linting tools for this project)
	$(info $(NULL)	test			- run tests for this project)
	$(info $(NULL)	test_clean		- runs cleanup of the test cache)
	$(info $(NULL)	test_coverage		- run tests for this project, with coverage reports)
	$(info $(NULL)	test_race		- run tests for this project, with race detection)
	$(info $(NULL))
	@:

# deps_get downloads dependencies for the project
deps_get :
	$(info $(NULL))
	go mod download
	go mod vendor
	@echo

# deps_update updates dependencies for the project
deps_update :
	$(info $(NULL))
	go get -t -u ./...
	go mod vendor
	@echo

# deps_tidy cleans dependencies for the project
deps_tidy :
	$(info $(NULL))
	go mod tidy
	@echo

# gofmt runs gofmt on directories
gofmt :
	$(info $(NULL))
	gofmt -w $(GO_FMT_DIRS)
	@echo

# lint_clean cleans the linting tools cache
lint_clean :
	$(info $(NULL))
	golangci-lint cache clean
	@echo

# lint_run runs linting tools for this project
lint_run :
	$(info $(NULL))
	golangci-lint run $(LINT_DIRS)
	@echo

# test runs the tests for this project
test :
	$(info $(NULL))
	go test $(TEST_DIRS)
	@echo

# test_clean cleans the test cache
test_clean :
	$(info $(NULL))
	go clean -testcache
	@echo

# test_coverage runs the tests for this project with coverage
test_coverage :
	$(info $(NULL))
	go test -cover $(TEST_DIRS)
	@echo

# test_race runs the tests for this project with race detection
test_race :
	$(info $(NULL))
	go test -race $(TEST_DIRS)
	@echo
