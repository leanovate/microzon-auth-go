# microzon-auth-go

## Issue Tracker

See: [microzon-auth](https://github.com/leanovate/microzon-auth)

## Setup a development environment

In go paths are important. Ensure that you checkout the project as described.

1. Install go (>= 1.5) as described in the [tutorial](https://golang.org/doc/install)
   * Mac users might just use homebrew instead: `brew install go`
2. Ensure that the `GOROOT` environment variable is correctly set. Best set it in your `.bashrc` or `.zshrc` 
  * On Mac with homebrew this would be: `export GOROOT=/usr/local/Cellar/go/1.5.1/libexec`
3. Decide where you want to work and set your `GOPATH` accordingly.
  * Best you create a workspace for each project you want to work on. E.g. like this:
    * `mkdir -p $HOME/workspaces/microzon`
    * Set your `GOPATH` like to: `export GOPATH=$HOME/workspaces/microzon`
4. Checkout the git repo at the correct place:
  * In the setup about you should do:

	    ```
	    mkdir -p $HOME/workspaces/microzon/src/github.com/leanovate
	    cd $HOME/workspaces/microzon/src/github.com/leanovate
	    git clone git@github.com:leanovate/microzon-auth-go.git
	    cd microzon-auth-go
	    ```
5. Just use `make`.
6. If you want to use an IDE like IntelliJ (with its go plugin). Use `$HOME/workspaces/microzon` as project root.

## Useful commands
* test the application:
  ```curl localhost:8080/v1/certificates```
  ```curl localhost:8080/v1/certificates | jq -r .[0].ski```
  ```curl localhost:8080/v1/certificates/<ski>```
* run server as docker:
  ```make docker && docker run -ti --rm -p 8080:8080 microzon-auth```

## License

[MIT Licence](http://opensource.org/licenses/MIT)
