package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

type room struct {
	clients map[*client]bool

	join    chan *client
	leave   chan *client
	forward chan []byte
}

func newRoom() *room {
	return &room{
		forward: make(chan []byte),
		join:    make(chan *client),
		leave:   make(chan *client),

		clients: make(map[*client]bool),
	}
}

func (r *room) run() {
	log.Printf("WebSocket room running with %d clients", len(r.clients))

	for {
		select {
		case client := <-r.join:
			r.clients[client] = true

		case client := <-r.leave:
			delete(r.clients, client)
			close(client.receive)

		case msg := <-r.forward:

			for client := range r.clients {
				client.receive <- msg
			}

		}
	}
}

const (
	socketBufferSize  = 1024
	messageBufferSize = 256
)

var upgrader = &websocket.Upgrader{ReadBufferSize: socketBufferSize, WriteBufferSize: socketBufferSize}

func (r *room) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	socket, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Fatal("ServeHTTP", err)
		return

	}
	client := &client{
		socket:  socket,
		receive: make(chan []byte, messageBufferSize),
		room:    r,
	}
	r.join <- client
	defer func() { r.leave <- client }()
	go client.write()
	client.read()
}
