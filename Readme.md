##### GitHub OAuth HTTP handler

See <https://godoc.org/github.com/kr/githubauth> for documentation.

###### Example

```go
func keys() []*[32]byte{
    // e.g. faba0c08be7474a785b272c4f4154c998c0943b51e662637be11b1a0ecda43b3
    key, err := hex.DecodeString(os.Getenv("KEY"))
    if err != nil {
        log.Fatal("Invalid key %v: %v\n", key, err)
    }
    if len(key) != 32 {
        log.Fatal("%v wasn't 32 bytes\n")
    }

    var key_array [32]byte
    copy(key_array[:], key)
    return []*[32]byte{&key_array}

}

h := &githubauth.Handler{
	RequireOrg:   "mycorp",
	Keys:         keys(),
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
}
http.ListenAndServe(":8080", h)
```
