using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using MissionPlanner.Comms;

namespace UBLOXDump
{
    internal class Program
    {
        private static readonly BinaryWriter bw =
            new BinaryWriter(File.Open("data.raw", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read));

        private static byte UBX_class;
        private static byte UBX_id;
        private static byte UBX_payload_length_hi;
        private static readonly int UBX_MAXPAYLOAD = 1000;
        private static byte ck_a;
        private static byte ck_b;
        private static byte UBX_payload_length_lo;
        private static byte UBX_ck_a;
        private static byte UBX_ck_b;
        private static int UBX_payload_counter;
        private static readonly byte[] UBX_buffer = new byte[256];
        private static int UBX_step;
        private static uploadreq req;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="file">raw dump</param>
        /// <param name="outputfile">output</param>
        /// <param name="startoffset">Memory location</param>
        /// <param name="secondsoffset">Flash location</param>
        private static void ExtractPacketAddresses(string file, string outputfile, int startoffset,
            int secondsoffset = 0, bool m8 = false)
        {
            if (!File.Exists(file))
                return;

            TextWriter tw = new StreamWriter(outputfile);

            var br = new BinaryReader(File.OpenRead(file));

            // 0x1420 - 6m
            // 0x3e4c - 7n

            br.BaseStream.Seek(startoffset, SeekOrigin.Begin);

            var lowestoffset = uint.MaxValue;

            while (br.BaseStream.Position < (startoffset + 2000))
            {
                var posstart = br.BaseStream.Position;
                var addr = br.ReadUInt32();
                if (addr != 0)
                    lowestoffset = Math.Min(addr, lowestoffset);
                br.BaseStream.Seek(2, SeekOrigin.Current);
                var clas = br.ReadByte();
                var subclas = br.ReadByte();
                br.BaseStream.Seek(12, SeekOrigin.Current);

                var pos = br.BaseStream.Position;

                ulong ch = 0;

                if (br.BaseStream.Length > addr)
                {
                    br.BaseStream.Seek(addr, SeekOrigin.Begin);

                    ch = br.ReadUInt64();

                    br.BaseStream.Seek(pos, SeekOrigin.Begin);
                }

                tw.WriteLine(posstart.ToString("X") + "\t" + clas.ToString("X") + "\t" + subclas.ToString("X") + "\t" +
                             addr.ToString("X") + "\t" + ch.ToString("X"));
            }

            //
            while (br.BaseStream.Position < (startoffset + 2000 + 320))
            {
                var addr = br.ReadUInt32();
                tw.WriteLine(addr.ToString("X"));
            }

            tw.WriteLine("Message in FW");

            //second
            if (secondsoffset > 0)
            {
                br.BaseStream.Seek(secondsoffset, SeekOrigin.Begin);

                try
                {
                    while (br.BaseStream.Position < (secondsoffset + 0x3e0))
                    {
                        var posstart = br.BaseStream.Position;

                        var clas = br.ReadByte();
                        var subclas = br.ReadByte();

                        br.BaseStream.Seek(2, SeekOrigin.Current);

                        var addr = br.ReadUInt32();

                        if (!m8)
                            br.BaseStream.Seek(4, SeekOrigin.Current);

                        tw.WriteLine(posstart.ToString("X") + "\t" + clas.ToString("X") + "\t" + subclas.ToString("X") +
                                     "\t" + addr.ToString("X"));
                    }
                }
                catch
                {
                }
            }

            tw.Close();

            br.Close();
        }

        private static void pollmessage(Stream port, byte[] header, byte clas, byte subclass)
        {
            //B5 62 02 31 00 00 33 9B 

            byte[] datastruct1 = {clas, subclass, 0, 0};

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        private static void turnon(Stream port, byte[] header, byte clas, byte subclass)
        {
            //B5 62 06 01 03 00 02 30 01 3D A6

            byte[] datastruct1 = {0x6, 0x1, 0x3, 0x0, clas, subclass, 1};

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        private static void Main(string[] args)
        {
            ExtractPacketAddresses("ublox 6mdata.raw", "Addrneo6m.txt", 0x1420, 0x26ddf4);

            ExtractPacketAddresses("6mdata.raw", "Addrneo6m-2.txt", 0x1420, 0x26ddf4);

            ExtractPacketAddresses("datalea6h.raw", "Addrlea6h.txt", 0x3e4c, 0x8546dc);

            ExtractPacketAddresses("datalea6h-nu602.raw", "Addrlea6hnu602.txt", 0x3e4c, 0x8546dc);

            ExtractPacketAddresses("dataneo7n.raw", "Addrneo7n.txt", 0x20001188, 0x862f0c);

            ExtractPacketAddresses("UBX_M8_301_HPG_111_REFERENCE_NEOM8P2.b45d5e63c7aa261bd58dfbcbc22bad68.bin",
                "Addrm8p.txt", 0, 0x6df34, true);

            ExtractPacketAddresses("EXT_G60_LEA-6H.fd1146bafac24b1347701312d42bb698.bin",
                "Addrlea6h-2.txt", 0, 0x546dc);

            ExtractPacketAddresses("FW101_EXT_TITLIS.42ec35ce38d201fd723f2c8b49b6a537.bin",
                "Addr7.txt", 0, 0x62f0c);

            ExtractPacketAddresses("UBLOX_M8_201.89cc4f1cd4312a0ac1b56c790f7c1622.bin",
                "Addr8_201.txt", 0, 0x739e8);

            ExtractPacketAddresses("UBX_M8_301_SPG.911f2b77b649eb90f4be14ce56717b49.bin",
                "Addr8_301.txt", 0, 0x7904c, true);
           
            
               return;

            ICommsSerial port;// = /*new TcpSerial();*/ //new SerialPort("com35" ,115200);
            port = new MissionPlanner.Comms.SerialPort();

            port.PortName = "com10";
            port.BaudRate = 115200;

            // mp internal pass
            //port.PortName = "127.0.0.1";
            //port.BaudRate = 500;

            port.ReadBufferSize = 1024*1024;

            port.Open();

            /*
             * 
             * ?????
0x00800000 0x80000 flash
0x20000000 0x20000 ram
0x20080000 0x20000 ram
0x00200000 0x8000 rom
             * 
For ublox6 ROM7.03 use: 

to enable RXM-RAW - addr 000016c8
b5 62 09 01 10 00 c8 16 00 00 00 00 00 00 97 69 21 00 00 00 02 10 2b 22


to enable RXM-SFRB - addr 0000190c
b5 62 09 01 10 00 0c 19 00 00 00 00 00 00 83 69 21 00 00 00 02 11 5f f0

             */

            var rxmraw6m = new downloadreq();
            rxmraw6m.clas = 0x9;
            rxmraw6m.subclass = 0x1;
            rxmraw6m.length = 0x10;
            rxmraw6m.flags = 0;
            rxmraw6m.startaddr = 0x16c8;
            rxmraw6m.data = new byte[] {0x97, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x10};

            var rxmsfrb6m = new downloadreq();
            rxmsfrb6m.clas = 0x9;
            rxmsfrb6m.subclass = 0x1;
            rxmsfrb6m.length = 0x10;
            rxmsfrb6m.flags = 0;
            rxmsfrb6m.startaddr = 0x190c;
            rxmsfrb6m.data = new byte[] {0x83, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x11};

            var rxmraw6h = new downloadreq();
            rxmraw6h.clas = 0x9;
            rxmraw6h.subclass = 0x1;
            rxmraw6h.length = 0x10;
            rxmraw6h.flags = 0;
            rxmraw6h.startaddr = 0x40F4;
            rxmraw6h.data = new byte[] {0xe7, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x10};

            var rxmsfrb6h = new downloadreq();
            rxmsfrb6h.clas = 0x9;
            rxmsfrb6h.subclass = 0x1;
            rxmsfrb6h.length = 0x10;
            rxmsfrb6h.flags = 0;
            rxmsfrb6h.startaddr = 0x4360;
            rxmsfrb6h.data = new byte[] {0xd3, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x11};

            byte[] turnonbytes = {0, 1, 0, 0, 0, 0, 0, 0};

            byte[] header = {0xb5, 0x62};

            /*
             * Load FW binary 'C:\Users\hog\Downloads\NL602-patched-fw (1).bin'
            Binary check success, G60 image valid.
            Version: 7.03 (45970) Mar 17 2011 16:26:24
            FLASH Base:          0x800000
            FW Base:             0x800000
            FW Start:            0x800048
            FW End:              0x860AD4
            FW Size:             0x60ADC
             * 
             * Identifying Flash
            Flash: ManID=0x90, DevID=0x90
             * 
             * firmware: 0x200000
             */

            //turnon(port, header, 2, 0x20);
            //turnon(port, header, 2, 0x12);
            //turnon(port, header, 2, 0x23);
            //turnon(port, header, 2, 0x24);
            //turnon(port, header, 2, 0x51);
            //turnon(port, header, 2, 0x52);

            // turnon(port.BaseStream, header, 3, 0xA);
            // turnon(port.BaseStream, header, 3, 0xF);

            //writepacket(port.BaseStream, header, rxmraw);
            //writepacket(port.BaseStream, header, rxmsfrb);

            //writepacket(port.BaseStream, header, rxmraw6h);
            //writepacket(port.BaseStream, header, rxmsfrb6h);

            //writepacket(port.BaseStream, header, rxmraw6m);
            //writepacket(port.BaseStream, header, rxmsfrb6m);

            //return;

            //turnon(port.BaseStream, header, 2, 0x10);
            //turnon(port.BaseStream, header, 2, 0x11);

            //testmsg.startaddr += 8;
            //testmsg.data = turnonbytes;
            //writepacket(port.BaseStream, header, testmsg);


            /*
            System.Threading.Thread.Sleep(200);

            while (port.IsOpen)
            {

                while (port.BytesToRead > 0)
                {
                    byte data = (byte)port.ReadByte();

                    // Console.Write("{0,2:x}",data);

                    processbyte(data);
                }

            }

            port.Close();

           // Console.ReadLine();

            return;
             */


            // dump rom/memory

            req = new uploadreq();
            req.clas = 0x9;
            req.subclass = 0x2;
            req.length = 12;
            req.startaddr = 0;
            req.datasize = 128;
            req.flags = 0;

            var deadline = DateTime.MinValue;
            uint lastaddr = 0;

            while (port.IsOpen)
            {
                // determine when to send a new/next request
                if (deadline < DateTime.Now || lastaddr != req.startaddr)
                {
                    var datastruct = StaticUtils.StructureToByteArray(req);

                    var checksum = ubx_checksum(datastruct, datastruct.Length);

                    port.Write(header, 0, header.Length);
                    port.Write(datastruct, 0, datastruct.Length);
                    port.Write(checksum, 0, checksum.Length);

                    deadline = DateTime.Now.AddMilliseconds(200);
                    lastaddr = req.startaddr;
                }

                Thread.Sleep(1);

                while (port.BytesToRead > 0)
                {
                    var data = (byte) port.ReadByte();

                    // Console.Write("{0,2:x}",data);

                    processbyte(data);
                }
            }
        }

        private static void writepacket(Stream port, byte[] header, object data)
        {
            var datastruct1 = StaticUtils.StructureToByteArray(data);

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);

            var all = new byte[header.Length + datastruct1.Length + checksum1.Length];

            Array.Copy(header, 0, all, 0, header.Length);
            Array.Copy(datastruct1, 0, all, 2, datastruct1.Length);
            Array.Copy(checksum1, 0, all, all.Length - 2, checksum1.Length);

            for (var a = 0; a < all.Length; a++)
            {
                Console.Write(" " + all[a].ToString("X"));
            }
            Console.WriteLine();
        }

        private static void processbyte(byte data)
        {
            switch (UBX_step) //Normally we start from zero. This is a state machine
            {
                case 0:
                    if (data == 0xB5) // UBX sync char 1
                        UBX_step++; //OH first data packet is correct, so jump to the next step
                    break;
                case 1:
                    if (data == 0x62) // UBX sync char 2
                        UBX_step++; //ooh! The second data packet is correct, jump to the step 2
                    else
                        UBX_step = 0; //Nop, is not correct so restart to step zero and try again.     
                    break;
                case 2:
                    UBX_class = data;
                    ubx_checksum(UBX_class);
                    UBX_step++;
                    break;
                case 3:
                    UBX_id = data;
                    ubx_checksum(UBX_id);
                    UBX_step++;
                    break;
                case 4:
                    UBX_payload_length_hi = data;
                    ubx_checksum(UBX_payload_length_hi);
                    UBX_step++;
                    // We check if the payload lenght is valid...
                    if (UBX_payload_length_hi >= UBX_MAXPAYLOAD)
                    {
                        UBX_step = 0; //Bad data, so restart to step zero and try again.     
                        ck_a = 0;
                        ck_b = 0;
                    }
                    break;
                case 5:
                    UBX_payload_length_lo = data;
                    ubx_checksum(UBX_payload_length_lo);
                    UBX_step++;
                    UBX_payload_counter = 0;
                    break;
                case 6: // Payload data read...
                    if (UBX_payload_counter < UBX_payload_length_hi)
                        // We stay in this state until we reach the payload_length
                    {
                        UBX_buffer[UBX_payload_counter] = data;
                        ubx_checksum(data);
                        UBX_payload_counter++;
                        if (UBX_payload_counter == UBX_payload_length_hi)
                            UBX_step++;
                    }
                    break;
                case 7:
                    UBX_ck_a = data; // First checksum byte
                    UBX_step++;
                    break;
                case 8:
                    UBX_ck_b = data; // Second checksum byte

                    // We end the GPS read...
                    if ((ck_a == UBX_ck_a) && (ck_b == UBX_ck_b))
                    {
                        // Verify the received checksum with the generated checksum.. 
                        // Parse the new GPS packet


                        if (UBX_class == 0x9 && UBX_id == 0x2)
                        {
                            var resp = UBX_buffer.ByteArrayToStructure<uploadresp>(0);

                            Console.WriteLine("{0:X}", resp.startaddr);

                            bw.Seek((int) resp.startaddr, SeekOrigin.Begin);
                            bw.Write(resp.data, 0, (int) req.datasize);

                            if (req.startaddr == resp.startaddr)
                                req.startaddr += req.datasize;

                            if (req.startaddr == 0x100000)
                                req.startaddr = 0x200000;

                            if (req.startaddr == 0x300000)
                                req.startaddr = 0x800000;
                            //req.startaddr += 256*1000;
                        }
                        else
                        {
                            Console.WriteLine(DateTime.Now + "we have a packet 0x" + UBX_class.ToString("X") + " 0x" +
                                              UBX_id.ToString("X") + " " + UBX_payload_counter);
                        }
                    }
                    // Variable initialization
                    UBX_step = 0;
                    ck_a = 0;
                    ck_b = 0;

                    break;
            }
        }

        private static void ubx_checksum(byte ubx_data)
        {
            ck_a += ubx_data;
            ck_b += ck_a;
        }

        private static byte[] ubx_checksum(byte[] packet, int size)
        {
            uint a = 0x00;
            uint b = 0x00;
            var i = 0;
            while (i < size)
            {
                a += packet[i++];
                b += a;
            }

            var ans = new byte[2];

            ans[0] = (byte) (a & 0xFF);
            ans[1] = (byte) (b & 0xFF);

            return ans;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct uploadresp
        {
            public readonly uint startaddr;
            public readonly uint datasize;
            public readonly uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] public readonly byte[] data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct downloadreq
        {
            public byte clas;
            public byte subclass;
            public ushort length;
            public uint startaddr;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct uploadreq
        {
            public byte clas;
            public byte subclass;
            public ushort length;
            public uint startaddr;
            public uint datasize;
            public uint flags;
        }
    }
}