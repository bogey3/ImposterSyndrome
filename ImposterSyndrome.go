package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"strconv"
	"time"
)

type Player struct{
	id int
	name string
	colour string
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

const RED = 0
const BLUE = 1
const GREEN = 2
const PINK = 3
const ORANGE = 4
const YELLOW = 5
const BLACK = 6
const WHITE = 7
const PURPLE = 8
const BROWN = 9
const CYAN = 10
const LIME = 11
const MAROON = 12
const ROSE = 13
const BANANA = 14
const GRAY = 15
const TAN = 16
const CORAL = 17

var players map[int]Player

func playerColour(colour int)string{
	switch colour {
	case RED:
		return "Red"
	case BLUE:
		return "Blue"
	case GREEN:
		return "Green"
	case PINK:
		return "Pink"
	case ORANGE:
		return "Orange"
	case YELLOW:
		return "Yellow"
	case BLACK:
		return "Black"
	case WHITE:
		return "White"
	case PURPLE:
		return "Purple"
	case BROWN:
		return "Brown"
	case CYAN:
		return "Cyan"
	case LIME:
		return "Lime"
	case MAROON:
		return "Maroon"
	case ROSE:
		return "Rose"
	case BANANA:
		return "Banana"
	case GRAY:
		return "Gray"
	case TAN:
		return "Tan"
	case CORAL:
		return "Coral"
	default:
		return "Unknown " + strconv.Itoa(colour)

	}
}

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
	// https://github.com/codyphobe/among-us-protocol/blob/master/01_packet_structure/03_the_structure_of_a_hazel_message.md
	length := int(binary.LittleEndian.Uint16(data[:2]))
	tag := int(data[2])
	if length+3 > len(data){
		return HazelMessage{tag, data[3:]}, []byte{}
	}
	payload := data[3:length+3]
	data = data[length+3:]
	return HazelMessage{tag, payload}, data
}

func decodePacket(data []byte){
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
						printPacket(SPAWN, data)
					}
				}
			}
		}
	}
}

func decodeSpawn(data []byte)([]Player, []Player) {
	imposters := []Player{}
	crewmates := []Player{}

	userPayload := HazelMessage{}
	//usersHazelMessages := []HazelMessage{}
	for len(data) > 0 {
		message := HazelMessage{}
		message, data = readHazelMessage(data)
		if message.tag == 1{
			userPayload = message
			break
		}
	}

	// https://github.com/codyphobe/among-us-protocol/blob/master/05_innernetobject_types/03_gamedata.md
	_, userPayload.payload = readPackedInt(userPayload.payload)
	for len(userPayload.payload) > 0 {
		playerData := HazelMessage{}
		playerData, userPayload.payload = readHazelMessage(userPayload.payload)

		colourId, hatId, petId, skinId, flags := 0,0,0,0, byte(0)
		name := string(playerData.payload[1:int(playerData.payload[0])+1])
		playerData.payload = playerData.payload[playerData.payload[0]+1:]
		colourId, playerData.payload = readPackedInt(playerData.payload)
		hatId, playerData.payload = readPackedInt(playerData.payload)
		petId, playerData.payload = readPackedInt(playerData.payload)
		skinId, playerData.payload = readPackedInt(playerData.payload)
		flags = playerData.payload[0]
		if playerColour(colourId) == "Unknown"{
			fmt.Println(name, colourId)
		}


		if (flags & 2) == 0 {
			crewmates = append(crewmates, Player{playerData.tag, name, playerColour(colourId), hatId, petId,skinId, flags})
		} else {
			imposters = append(imposters, Player{playerData.tag, name, playerColour(colourId), hatId, petId,skinId, flags})
		}
	}
	return crewmates, imposters
}

func printGame(crewmates []Player, imposters []Player){
	format := "| %-10s | %-10s || %-10s | %-10s |\n"
	fmt.Printf("+-------------------------++-------------------------+\n")
	fmt.Printf(format, "Crewmates", "Colour", "Imposters", "Colour")
	fmt.Printf("+-------------------------++-------------------------+\n")
	for i, crewmate := range(crewmates){
		imposter := Player{}
		if i < len(imposters){
			imposter = imposters[i]
		}
		fmt.Printf(format, crewmate.name, crewmate.colour, imposter.name, imposter.colour)
	}
	fmt.Printf("+-------------------------++-------------------------+\n\n")

}

func listenForInitial(device pcap.Interface, returnChan chan pcap.Interface, deviceFound chan bool, filter string){
	//This function will listen on an interface for packets on the ports used by AmongUs and then return that interface to the findInterface function through a channel
	buffer := int32(1600)
	handler, err := pcap.OpenLive(device.Name, buffer, false, time.Second)
	if err != nil {
		panic(err)
	}
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())

	go func() {
		//Wait for device to be found, then exit
		<- deviceFound
		handler.Close()
	}()

	for range source.Packets() {
		returnChan <- device
		close(deviceFound) // Close the deviceFound channel so all threads waiting for AmongUs traffic will exit
	}
}

func findInterface(filter string)pcap.Interface{
	//This function will find the interface used by AmongUs by listening on all interfaces for network traffic on the UDP ports used by AmongUs
	devices, err := pcap.FindAllDevs()
	if err != nil{
		panic(err)
	}
	returnChan := make(chan pcap.Interface)
	deviceFound := make(chan bool)

	for _, device := range devices {
		go listenForInitial(device, returnChan, deviceFound, filter)
	}
	return <- returnChan
}


func printPacket(packetType int, data []byte){
	if packetType == SPAWN {
		crewmates, imposters := decodeSpawn(data)
		if len(imposters)+len(crewmates) >= 4 {
			printGame(crewmates, imposters)
		}
	}
}

func main() {
	players = make(map[int]Player)
	filter := "udp port 22023 or udp port 22123 or udp port 22223 or udp port 22323 or udp port 22423 or udp port 22523 or udp port 22623 or udp port 22723 or udp port 22823 or udp port 22923"
	fmt.Print("Waiting for game traffic\r")
	internetConnectedInterface := findInterface(filter)
	fmt.Println("Using interface:", internetConnectedInterface.Description)

	buffer := int32(1600)

	handler, err := pcap.OpenLive(internetConnectedInterface.Name, buffer, false, pcap.BlockForever)
	if err != nil{
		panic(err)
	}

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	fmt.Print("Listening for spawn...\r")
	for packet := range source.Packets() {
		go decodePacket(packet.Data()[42:])
	}
}
