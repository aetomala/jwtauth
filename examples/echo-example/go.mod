module github.com/aetomala/jwtauth/examples/echo-example

go 1.23.0

require (
	github.com/aetomala/jwtauth v0.2.0-beta
	github.com/labstack/echo/v4 v4.12.0
)

replace github.com/aetomala/jwtauth => ../..
