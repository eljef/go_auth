.PHONY: help all deps_get deps_update gofmt lint_clean lint_install lint_run test test_clean test_coverage \
test_missing_coverage test_race

NULL :=
VERSION := 0.0.1

# all runs help
all : help

# help lists out targets
help :
	$(info $(NULL))
	$(info ** Available Targets **)
	$(info $(NULL))
	$(info $(NULL)	deps_get		- download the dependencies for this project to the vendor folder)
	$(info $(NULL)	deps_update		- update the dependencies for this project)
	$(info $(NULL)	gofmt			- runs gofmt, formatting all project source files)
	$(info $(NULL)	lint_clean		- cleans the lint tools cache)
	$(info $(NULL)	lint_install		- installs linting tools for this project on this system)
	$(info $(NULL)	lint_run		- runs linting tools for this project)
	$(info $(NULL)	test			- run tests for this project)
	$(info $(NULL)	test_clean		- runs cleanup of the test cache)
	$(info $(NULL)	test_coverage		- run tests for this project, with coverage reports)
	$(info $(NULL)	test_missing_coverage	- run tests for this project, outputting coverage reports with less than 100% coverage)
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
	@echo

# gofmt runs gofmt on directories
gofmt :
	$(info $(NULL))
	gofmt -w ./pkg/
	@echo

# lint_clean cleans the linting tools cache
lint_clean :
	$(info $(NULL))
	golangci-lint cache clean
	@echo

# lint_install installs linting tools for this project on this system
lint_install :
	$(info $(NULL))
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	go get -u github.com/timakin/bodyclose
	go get -u github.com/tsenart/deadcode
	go get -u github.com/mibk/dupl
	go get -u github.com/kisielk/errcheck
	go get -u 4d63.com/gochecknoinits
	go get -u github.com/uudashr/gocognit/cmd/gocognit
	go get -u github.com/jgautheron/goconst/cmd/goconst
	go get -u github.com/alecthomas/gocyclo
	go get -u golang.org/x/lint/golint
	go get -u github.com/securego/gosec/cmd/gosec/...
	go get -u github.com/gordonklaus/ineffassign
	go get -u github.com/mdempsky/maligned
	go get -u github.com/alexkohler/nakedret
	go get -u github.com/kyoh86/scopelint
	go get -u gitlab.com/opennota/check/cmd/structcheck
	go get -u github.com/mdempsky/unconvert
	go get -u mvdan.cc/unparam
	go get -u gitlab.com/opennota/check/cmd/varcheck
	go get -u github.com/cweill/gotests/...
	go get -u honnef.co/go/tools/...
	@echo

# lint_run runs linting tools for this project
lint_run :
	$(info $(NULL))
	golangci-lint run ./pkg/...

# test runs the tests for this project
test :
	$(info $(NULL))
	go test -p 1 ./pkg/...
	@echo

# test_clean cleans the test cache
test_clean :
	$(info $(NULL))
	go clean -testcache
	@echo

# test_coverage runs the tests for this project with coverage
test_coverage :
	$(info $(NULL))
	go test -p 1 -cover ./pkg/...
	@echo

# test_missing_coverage runs the test for this project with coverage, outputting only tests with less than 100% coverage
test_missing_coverage :
	$(info $(NULL))
	@echo Missing test coverage will show below
	@echo
	@go test -p 1 -cover ./pkg/... | grep -v -e "100.0" || echo "no packages missing coverage"
	@echo

# test_race runs the tests for this project with race detection
test_race :
	$(info $(NULL))
	go test -p 1 -race ./pkg/...
	@echo
