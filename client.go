// package main

// import (
// 	"log"

// 	"github.com/gorilla/websocket"
// )

// type client struct {
// 	socket  *websocket.Conn
// 	receive chan []byte
// 	room    *room
// }

// func (c *client) read() {
// 	defer c.socket.Close()
// 	for {
// 		_, msg, err := c.socket.ReadMessage()
// 		if err != nil {
// 			log.Printf("Error reading message: %v", err)
// 			break
// 			// return
// 		}
// 		c.room.forward <- msg

// 	}

// }

// func (c *client) readMessages() {
// 	defer c.socket.Close()
// 	for {
// 		_, msg, err := c.socket.ReadMessage()
// 		if err != nil {
// 			log.Printf("Error reading message from client: %v", err)
// 			break
// 		}
// 		log.Printf("Received message from client: %s", msg)
// 		c.room.forward <- msg
// 	}
// }
// func (c *client) write() {
// 	defer c.socket.Close()
// 	for msg := range c.receive {
// 		err := c.socket.WriteMessage(websocket.TextMessage, msg)
// 		if err != nil {
// 			log.Printf("Error writing message: %v", err)
// 			break
// 			// return
// 		}
// 	}
// }
// In client.go

package main

import (
	"log"

	"github.com/gorilla/websocket"
)

type client struct {
	socket  *websocket.Conn
	receive chan []byte
	room    *room
}

func (c *client) read() {
	defer c.socket.Close()
	for {
		_, msg, err := c.socket.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}
		c.room.forward <- msg
	}
}

func (c *client) write() {
	defer c.socket.Close()
	for msg := range c.receive {
		err := c.socket.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			log.Printf("Error writing message: %v", err)
			break
		}
	}
}
