package karaoke

import (
	"context"
	"errors"
	"github.com/redis/go-redis/v9"
	"time"
)

const SessionTTL = 7 * 86400
const CaptchaTTL = 300
const sessionPrefix = "karaoke:session:"
const captchaPrefix = "karaoke:captcha:"

type Cache interface {
	ReserveRequest(context.Context, string, string, string) (bool, error)
	Captcha(context.Context, string, string, string) error
	CaptchaImage(context.Context, string) (string, error)
	TakeCaptcha(context.Context, string) (string, error)
	Counter(context.Context, string) (int64, error)
	ReserveLogin(context.Context, string, bool) (int64, error)
	SaveSession(context.Context, string, string, string, string) error
	Session(context.Context, string) (map[string]string, error)
	UseSession(context.Context, string, string, string, string) (bool, error)
	Delete(context.Context, string) error
	RevokeUser(context.Context, string) error
}
type RedisCache struct{ client *redis.Client }

func NewRedisCache(client *redis.Client) *RedisCache { return &RedisCache{client} }

var captchaTake = redis.NewScript(`local v=redis.call('GET',KEYS[1]); redis.call('DEL',KEYS[1],KEYS[1]..':image'); return v`)

// Admission is atomic across global, IP and account budgets. Rejected requests
// do not create keys or extend the fixed window, even with rotating usernames.
var requestReserve = redis.NewScript(`for i,k in ipairs(KEYS) do if tonumber(redis.call('GET',k) or '0')>=tonumber(ARGV[i]) then return 0 end end; for i,k in ipairs(KEYS) do local n=redis.call('INCR',k); if n==1 then redis.call('EXPIRE',k,60) end end; return 1`)
var loginReserve = redis.NewScript(`local n=tonumber(redis.call('GET',KEYS[1]) or '0'); if n>=3 and ARGV[1]~='1' then return -1 end; n=redis.call('INCR',KEYS[1]); redis.call('EXPIRE',KEYS[1],86400); return n`)
var sessionSave = redis.NewScript(`if redis.call('EXISTS',KEYS[1])~=0 then return 0 end; local g=redis.call('GET',KEYS[2]) or '0'; redis.call('HSET',KEYS[1],'user_id',ARGV[1],'csrf',ARGV[2],'password_fp',ARGV[3],'generation',g); redis.call('EXPIRE',KEYS[1],ARGV[4]); return 1`)
var sessionUse = redis.NewScript(`local g=redis.call('GET',KEYS[2]) or '0'; if redis.call('HGET',KEYS[1],'user_id')~=ARGV[1] or redis.call('HGET',KEYS[1],'csrf')~=ARGV[2] or redis.call('HGET',KEYS[1],'password_fp')~=ARGV[3] or redis.call('HGET',KEYS[1],'generation')~=g then return 0 end; redis.call('EXPIRE',KEYS[1],ARGV[4]); return 1`)

func userGeneration(id string) string { return "karaoke:user-generation:" + id }
func cacheContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 2*time.Second)
}
func (c *RedisCache) ReserveRequest(ctx context.Context, action, ip, account string) (bool, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	global, perIP, perAccount := 60, 20, 10
	budget := "credentials"
	if action == "captcha" {
		budget, global = "captcha", 200
	} else if action != "login" && action != "register" && action != "password" {
		return false, errors.New("invalid account admission action")
	}
	keys := []string{"karaoke:rate:" + budget + ":global", "karaoke:rate:" + action + ":ip:" + hash(ip)}
	limits := []any{global, perIP}
	if action != "captcha" {
		keys = append(keys, "karaoke:rate:"+action+":account:"+hash(account))
		limits = append(limits, perAccount)
	}
	n, err := requestReserve.Run(ctx, c.client, keys, limits...).Int()
	return n == 1, err
}
func (c *RedisCache) Captcha(ctx context.Context, id, hash, answer string) error {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	p := c.client.TxPipeline()
	p.Set(ctx, captchaPrefix+id, hash, CaptchaTTL*time.Second)
	p.Set(ctx, captchaPrefix+id+":image", answer, CaptchaTTL*time.Second)
	_, err := p.Exec(ctx)
	return err
}
func (c *RedisCache) CaptchaImage(ctx context.Context, id string) (string, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	v, err := c.client.Get(ctx, captchaPrefix+id+":image").Result()
	if errors.Is(err, redis.Nil) {
		err = nil
	}
	return v, err
}
func (c *RedisCache) TakeCaptcha(ctx context.Context, id string) (string, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	v, err := captchaTake.Run(ctx, c.client, []string{captchaPrefix + id}).Text()
	if errors.Is(err, redis.Nil) {
		err = nil
	}
	return v, err
}
func (c *RedisCache) Counter(ctx context.Context, key string) (int64, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	v, err := c.client.Get(ctx, key).Int64()
	if errors.Is(err, redis.Nil) {
		err = nil
	}
	return v, err
}
func (c *RedisCache) ReserveLogin(ctx context.Context, key string, captcha bool) (int64, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	verified := "0"
	if captcha {
		verified = "1"
	}
	return loginReserve.Run(ctx, c.client, []string{key}, verified).Int64()
}
func (c *RedisCache) SaveSession(ctx context.Context, key, id, csrf, fp string) error {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	v, err := sessionSave.Run(ctx, c.client, []string{key, userGeneration(id)}, id, csrf, fp, SessionTTL).Int()
	if err == nil && v != 1 {
		return errors.New("session identifier collision")
	}
	return err
}
func (c *RedisCache) Session(ctx context.Context, key string) (map[string]string, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	return c.client.HGetAll(ctx, key).Result()
}
func (c *RedisCache) UseSession(ctx context.Context, key, id, csrf, fp string) (bool, error) {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	v, err := sessionUse.Run(ctx, c.client, []string{key, userGeneration(id)}, id, csrf, fp, SessionTTL).Int()
	return v == 1, err
}
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	return c.client.Del(ctx, key).Err()
}
func (c *RedisCache) RevokeUser(ctx context.Context, id string) error {
	ctx, cancel := cacheContext(ctx)
	defer cancel()
	return c.client.Incr(ctx, userGeneration(id)).Err()
}
