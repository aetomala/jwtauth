package keys

// PemPrefix returns the effective PEM key prefix for testing purposes only.
func (r *RedisKeyStore) PemPrefix() string { return r.pemPrefix }

// MetaPrefix returns the effective metadata key prefix for testing purposes only.
func (r *RedisKeyStore) MetaPrefix() string { return r.metaPrefix }
