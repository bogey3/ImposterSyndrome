# ImposterSyndrome
This is a packet sniffer for Among Us. It will inform you which players are crewmates, and which are imposters.

## Prerequisites
This program relies on gopacket, which relies on winpcap or npcap on windows, please install one of those before running this program.

## Important Note
Please don't ruin the game, I created this as a learning experience and wanted to share it, but please don't ruin games of Among Us.

## Sample Output
```
Using Intel(R) Ethernet Connection I219-V
Listening for spawn packet...
+-------------------------++-------------------------+
| Crewmates  | Colour     || Imposters  | Colour     |
+-------------------------++-------------------------+
| Limahm     | Coral      || Carbous    | Green      |
| Ousloe     | Red        || Darkbook   | White      |
| Meanstar   | Lime       || Sunnysoda  | Yellow     |
| Ovalcrowd  | Cyan       ||            |            |
| Lotin      | Rose       ||            |            |
| Phorek     | Orange     ||            |            |
| Lexpow     | Banana     ||            |            |
| Misfish    | Pink       ||            |            |
| Phoyx      | Gray       ||            |            |
+-------------------------++-------------------------+
```
