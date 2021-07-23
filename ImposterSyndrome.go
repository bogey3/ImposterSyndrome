package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type Player struct{
	id int
	name string
	colour int
	hat int
	pet int
	skin int
	flags byte
}

type HazelMessage struct{
	tag int
	payload []byte
}

const RELIABLE = byte(1)
const GAME_DATA = 5
const SPAWN = 4
const SKELD_SHIP_STATUS = 0 // https://github.com/codyphobe/among-us-protocol/blob/master/01_packet_structure/06_enums.md#spawntype
const MIRA_SHIP_STATUS = 5
const POLUS_SHIP_STATUS = 6
const DLEKS_SHIP_STATUS = 7
const AIRSHIP_STATUS = 8
var players map[int]Player

func readPackedInt(packed []byte)(int, []byte){
	newInt := 0
	shift := byte(0)
	bytesRemoved := 0
	for _, v := range packed{
		newInt |= (int(v) << int(shift))
		shift += 7
		bytesRemoved++
		if (v & byte(128)) < byte(128){
			break
		}
	}
	return newInt, packed[bytesRemoved:]
}

func readHazelMessage(data []byte)(HazelMessage, []byte){
	length := int(binary.LittleEndian.Uint16(data[:2]))
	tag := int(data[2])
	if length+3 > len(data){
		return HazelMessage{tag, data[3:]}, []byte{}
	}
	payload := data[3:length+3]
	data = data[length+3:]
	return HazelMessage{tag, payload}, data
}

func decodePacket(data []byte)(int, []byte){
	//This function will find the spawn packet and parse it
	if len(data) > 3 {
		packetType := data[0]
		if packetType == RELIABLE {
			data = data[1:]
			nonce := data[0:2]
			_ = nonce
			data = data[2:]
			message := HazelMessage{}
			message, data = readHazelMessage(data)
			if len(data) == 0 {
				data = message.payload
			}
			if message.tag == GAME_DATA && len(data) > 8 {
				gameId := data[:4]
				data = data[4:]
				_ = gameId
				gameDataMessage := HazelMessage{}
				gameDataMessage, _ = readHazelMessage(data)
				if gameDataMessage.tag == SPAWN{
					spawnType, _ := readPackedInt(gameDataMessage.payload)
					if spawnType == SKELD_SHIP_STATUS || spawnType == MIRA_SHIP_STATUS || spawnType == POLUS_SHIP_STATUS || spawnType == DLEKS_SHIP_STATUS || spawnType == AIRSHIP_STATUS{
						return SPAWN, data
					}
				}
			}
		}
	}
	return 0, []byte{}
}

func decodeSpawn(data []byte)([]string, []string) {
	imposters := []string{}
	crewmates := []string{}

	userPayload := HazelMessage{}
	usersHazelMessages := []HazelMessage{}
	for len(data) > 0 {
		message := HazelMessage{}
		message, data = readHazelMessage(data)
		if message.tag == 1{
			userPayload = message
			break
		}
	}

	if len(userPayload.payload) > 1 {
		_, userPayload.payload = readPackedInt(userPayload.payload)
		for len(userPayload.payload) > 0 {
			message := HazelMessage{}
			message, userPayload.payload = readHazelMessage(userPayload.payload)
			usersHazelMessages = append(usersHazelMessages, message)
		}
	}

	for _, userMessage := range usersHazelMessages{
		colourId, hatId, petId, skinId, flags := 0,0,0,0, byte(0)
		name := string(userMessage.payload[1:int(userMessage.payload[0])+1])
		userMessage.payload = userMessage.payload[userMessage.payload[0]+1:]
		colourId, userMessage.payload = readPackedInt(userMessage.payload)
		hatId, userMessage.payload = readPackedInt(userMessage.payload)
		petId, userMessage.payload = readPackedInt(userMessage.payload)
		skinId, userMessage.payload = readPackedInt(userMessage.payload)
		flags = userMessage.payload[0]
		players[userMessage.tag] = Player{userMessage.tag, name, colourId, hatId, petId,skinId, flags}

		if (flags & 2) == 0 {
			crewmates = append(crewmates, name)
		} else {
			imposters = append(imposters, name)
		}

	}
	return imposters, crewmates
}

func printGame(crewmates []string, imposters []string){
	format := "| %-10s | %-10s |\n"
	fmt.Printf("+------------+------------+\n")
	fmt.Printf(format, "Crewmates", "Imposters")
	fmt.Printf("+------------+------------+\n")
	for i, crewmate := range(crewmates){
		imposter := ""
		if i < len(imposters){
			imposter = imposters[i]
		}
		fmt.Printf(format, crewmate, imposter)
	}
	fmt.Printf("+------------+------------+\n\n")

}

func listenForInitial(device pcap.Interface, returnChan chan pcap.Interface, payload []byte, readyChan chan bool){
	//This function will listen on an interface for a specific packet and then return that interface to the findInterface function through a channel
	buffer := int32(1600)
	filter := "udp port 22023 and host na.mm.among.us"
	handler, err := pcap.OpenLive(device.Name, buffer, false, time.Second)
	if err != nil {
		panic(err)
	}

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())

	go func() {
		//Wait ten seconds then close the handler so the many packet capture threads can exit
		time.Sleep(time.Second * 10)
		handler.Close()
	}()
	readyChan <- true // Send a message on the channel to let the thread know it's ready to retrieve the packets
	for packet := range source.Packets() {
		if bytes.Equal(packet.Data()[42:], payload) {
			returnChan <- device
		}
	}
}

func findInterface()pcap.Interface{
	//This function will find the publicly routable interface by listening on all interfaces, then sending a specific packet
	//The packet that actually sends the interface is the one with internet access
	flag := []byte{1,2,3,4,5,6,7,8,9,8,7,6,5,4,3,2,1}
	returnChan := make(chan pcap.Interface)
	readyChan := make(chan bool)
	devices, err := pcap.FindAllDevs()
	if err != nil{
		panic(err)
	}
	for _, device := range devices {
		go listenForInitial(device, returnChan, flag, readyChan)
	}
	for range devices {
		<-readyChan // Recieve a message from each chan when it is ready to listen
	}
	conn, err := net.Dial("udp", "na.mm.among.us:22023")
	conn.Write(flag)
	conn.Close()
	gatewayDevice := <- returnChan
	return gatewayDevice
}


func printPacket(packetType int, data []byte){
	if packetType == SPAWN {
		imposters, crewmates := decodeSpawn(data)
		if len(imposters)+len(crewmates) >= 4 {
			printGame(crewmates, imposters)
		}
	}
}

func main() {
	players = make(map[int]Player)

	routeableInterface := findInterface()
	fmt.Println("Using", routeableInterface.Description)

	buffer := int32(1600)
	filter := "udp port 22023 or udp port 22123 or udp port 22223 or udp port 22323 or udp port 22423 or udp port 22523 or udp port 22623 or udp port 22723 or udp port 22823 or udp port 22923"

	handler, err := pcap.OpenLive(routeableInterface.Name, buffer, false, pcap.BlockForever)
	if err != nil{
		panic(err)
	}

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	fmt.Println("Listening for spawn packets...")
	for packet := range source.Packets() {
		packetType, data := decodePacket(packet.Data()[42:])
		printPacket(packetType, data)

	}
}
