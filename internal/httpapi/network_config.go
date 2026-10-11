package httpapi

import (
	"net"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func (p *Public) ConfigureNetwork(control *node.Service) { p.control = control }
func (p *Public) stunURLs(c *gin.Context) []string {
	if p.control != nil {
		if urls, e := p.control.STUNURLs(c.Request.Context(), p.settings.ServerName, p.settings.STUNPort); e == nil {
			return urls
		}
	}
	return []string{"stun:" + net.JoinHostPort(p.settings.ServerName, strconv.Itoa(p.settings.STUNPort))}
}
