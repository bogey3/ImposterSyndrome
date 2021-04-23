package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"regexp"
	"time"
)

const RELIABLE = byte(1)
const GAME_DATA = byte(5)
const SPAWN = byte(4)

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

func findPlayers(data []byte)[]int{
	startLen := len(data)
	data = data[bytes.Index(data, []byte{9, 0, 2})+3:]
	for data[0] == data[12]{
		data = data[12:]
	}
	cutLen := startLen-len(data)


	players := []int{}
	nameRegex, _ := regexp.Compile(`([\x00-\x0a])([^[:cntrl:]]+)`)
	playerRegex, _ := regexp.Compile(`([\x00-\x0a])([\x00-\x0a])([^[:cntrl:]]+)([\x80-\xff]{0,4}[\x00-\x7f]){4}`)
	names := nameRegex.FindAllSubmatch(data, -1)
	for _, matches := range names{
		if int(matches[1][0]) == len(matches[2]){
			index := bytes.Index(data, matches[0])
			if index > 0 && int(matches[1][0]) >= 1 && data[index-1] < 10 && data[index] <= 10{
				for _, v := range matches[2] {
					if bytes.Contains([]byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), []byte{v}) {
						players = append(players, index+cutLen)
						playerBytes := playerRegex.FindAllSubmatch(data[index-1:], 1)
						_=playerBytes
						break
					}
				}
			}
		}
	}
	return players
}

func decodePacket(data []byte)([]string, []string){
	//This function will find the spawn packet and parse it
	imposters := []string{}
	crewmates := []string{}

	packetType := data[0]
	if packetType == RELIABLE{
		data = data[1:]
		nonce := data[0:2]
		_=nonce
		data = data[2:]
		messageTag := data[0:3]
		data = data[3:]
		if messageTag[2] == GAME_DATA{
			gameId := data[:4]
			data = data[4:]
			_=gameId
			hazelMessageTag := data[:3]
			data = data[3:]
			if hazelMessageTag[2] == SPAWN{

				spawnType, ownerId, componentLengths := 0, 0, 0
				spawnType, data = readPackedInt(data)
				ownerId, data = readPackedInt(data)
				_,_=spawnType, ownerId
				spawnFlags := data[0]
				data = data[1:]
				_=spawnFlags
				componentLengths, data = readPackedInt(data)
				components := data[:componentLengths]
				_=components
				data = data[componentLengths:]

				playerIndexes := findPlayers(data)
				for _, index := range playerIndexes{
					playerData:= data[index:]
					colourId, hatId, petId, skinId, flags := 0,0,0,0,0
					name := string(playerData[1:int(data[index])+1])
					playerData = playerData[playerData[0]+1:]
					colourId, playerData = readPackedInt(playerData)
					hatId, playerData = readPackedInt(playerData)
					petId, playerData = readPackedInt(playerData)
					skinId, playerData = readPackedInt(playerData)
					flags, playerData = readPackedInt(playerData)
					_,_,_,_,_ = colourId, hatId, petId, skinId, name

					if (flags & 2) == 0 {
						crewmates = append(crewmates, name)
					} else {
						imposters = append(imposters, name)
					}

				}

			}
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

func listenForInitial(device pcap.Interface, returnChan chan pcap.Interface, payload []byte, quitChan chan bool){
	//This function will listen on an interface for a specific packet and then return that interface to the findInterface function through a channel
	go func() {
		buffer := int32(1600)
		filter := "udp port 22023 and host na.mm.among.us"
		handler, err := pcap.OpenLive(device.Name, buffer, false, pcap.BlockForever)
		defer handler.Close()
		if err != nil {
			panic(err)
		}

		if err := handler.SetBPFFilter(filter); err != nil {
			log.Fatal(err)
		}
		source := gopacket.NewPacketSource(handler, handler.LinkType())
		for packet := range source.Packets() {
			if bytes.Equal(packet.Data()[42:], payload) {
				returnChan <- device
			}
		}
	}()

	<-quitChan
}

func findInterface()pcap.Interface{
	//This function will find the publicly routable interface by listening on all interfaces, then sending a specific packet
	//The packet that actually sends the interface is the one with internet access
	flag := []byte{1,2,3,4,5,6,7,8,9,8,7,6,5,4,3,2,1}
	returnChan := make(chan pcap.Interface, 5)
	quitChan := make(chan bool)
	devices, err := pcap.FindAllDevs()
	if err != nil{
		panic(err)
	}
	for _, device := range devices {
		go listenForInitial(device, returnChan, flag, quitChan)
	}
	time.Sleep(time.Millisecond*500)
	conn, err := net.Dial("udp", "na.mm.among.us:22023")
	conn.Write(flag)
	conn.Close()
	gatewayDevice := <- returnChan
	for range devices {
		quitChan <- true
	}
	return gatewayDevice
}



func main() {

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
		imposters, crewmates := decodePacket(packet.Data()[42:])
		if len(imposters) + len(crewmates) >= 4{
			printGame(crewmates, imposters)
		}

	}
}
