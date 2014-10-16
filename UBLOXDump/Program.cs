using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using MissionPlanner.Comms;

namespace UBLOXDump
{
    class Program
    {
        static BinaryWriter bw = new BinaryWriter(File.Open("data.raw", FileMode.OpenOrCreate, FileAccess.ReadWrite,FileShare.Read));


        private static byte UBX_class;
        private static byte UBX_id;
        private static byte UBX_payload_length_hi;
        private static int UBX_MAXPAYLOAD = 1000;
        private static byte ck_a;
        private static byte ck_b;
        private static byte UBX_payload_length_lo;
        private static byte UBX_ck_a;
        private static byte UBX_ck_b;
        private static int UBX_payload_counter;
        static byte[] UBX_buffer = new byte[256];
        private static int UBX_step;
        static uploadreq req;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct uploadresp
        {
            public uint startaddr;
            public uint datasize;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] data;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct downloadreq
        {
            public byte clas;
            public byte subclass;
            public ushort length;
            public uint startaddr;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct uploadreq
        {
            public byte clas;
            public byte subclass;
            public ushort length;
            public uint startaddr;
            public uint datasize;
            public uint flags;
        }

        static void ExtractPacketAddresses(string file, string outputfile, int startoffset)
        {
            if (!File.Exists(file))
                return;

            TextWriter tw = new StreamWriter(outputfile);

            BinaryReader br = new BinaryReader(File.OpenRead(file));

            // 0x1420 - 6m
            // 0x3e4c - 7n

            br.BaseStream.Seek(startoffset, SeekOrigin.Begin);

            uint lowestoffset = uint.MaxValue;

            while (br.BaseStream.Position < (startoffset+2000))
            {
                long posstart = br.BaseStream.Position;
                uint addr = br.ReadUInt32();
                if (addr != 0)
                    lowestoffset = Math.Min(addr, lowestoffset);
                br.BaseStream.Seek(2, SeekOrigin.Current);
                byte clas = br.ReadByte();
                byte subclas = br.ReadByte();
                br.BaseStream.Seek(12, SeekOrigin.Current);

                long pos = br.BaseStream.Position;

                UInt64 ch = 0;

                if (br.BaseStream.Length > addr)
                {
                    br.BaseStream.Seek(addr, SeekOrigin.Begin);

                    ch = br.ReadUInt64();

                    br.BaseStream.Seek(pos, SeekOrigin.Begin);
                }

                tw.WriteLine(posstart.ToString("X")+"\t"+clas.ToString("X") + "\t" + subclas.ToString("X") + "\t" + addr.ToString("X") + "\t" + ch.ToString("X"));
            }

            //
            while (br.BaseStream.Position < (startoffset + 2000 + 320))
            {
                uint addr = br.ReadUInt32();
                tw.WriteLine(addr.ToString("X"));
            }

            br.BaseStream.Seek(lowestoffset, SeekOrigin.Begin);
            while (br.BaseStream.Position < (lowestoffset + 0x10000) && br.BaseStream.Length > (lowestoffset + 0x10000))
            {
                long pos =  br.BaseStream.Position;
                byte ch = br.ReadByte();

                if (ch == 0xb5)
                {
                    UInt64 chs = br.ReadUInt64();

                    tw.WriteLine("posible msg 0xb5 " + chs.ToString("X") + "\t" + pos.ToString("X"));
                }
            }

            tw.Close();

            br.Close();
        }

        static void pollmessage(Stream port, byte[] header, byte clas, byte subclass)
        {
             //B5 62 02 31 00 00 33 9B 

            byte[] datastruct1 = new byte[] { clas,subclass,0,0 };

            byte[] checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        static void turnon(Stream port, byte[] header, byte clas, byte subclass)
        {
            //B5 62 06 01 03 00 02 30 01 3D A6

            byte[] datastruct1 = new byte[] { 0x6,0x1, 0x3, 0x0, clas, subclass, 1 };

            byte[] checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        static void Main(string[] args)
        {
            ExtractPacketAddresses("ublox 6mdata.raw", "Addrneo6m.txt", 0x1420);

            ExtractPacketAddresses("dataneo7n.raw", "Addrneo7n.txt", 0x1420);

            ExtractPacketAddresses("datalea6h.raw", "Addrlea6h.txt", 0x3e4c);

            ExtractPacketAddresses("datalea6h-nu602.raw", "Addrlea6hnu602.txt", 0x3e4c);

            
            
            

              //  return;

            ICommsSerial port = new TcpSerial();//new SerialPort("com35",115200);
            port = new MissionPlanner.Comms.SerialPort();

            port.PortName = "com35";
            port.BaudRate = 115200;

            //port.PortName = "127.0.0.1";
            //port.BaudRate = 500;

            port.ReadBufferSize = 1024 * 1024;

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

            downloadreq rxmraw6m = new downloadreq();
            rxmraw6m.clas = 0x9;
            rxmraw6m.subclass = 0x1;
            rxmraw6m.length = 0x10;
            rxmraw6m.flags = 0;
            rxmraw6m.startaddr = 0x16c8;
            rxmraw6m.data = new byte[] { 0x97, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x10 };

            downloadreq rxmsfrb6m = new downloadreq();
            rxmsfrb6m.clas = 0x9;
            rxmsfrb6m.subclass = 0x1;
            rxmsfrb6m.length = 0x10;
            rxmsfrb6m.flags = 0;
            rxmsfrb6m.startaddr = 0x190c;
            rxmsfrb6m.data = new byte[] { 0x83, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x11 };

            downloadreq rxmraw6h = new downloadreq();
            rxmraw6h.clas = 0x9;
            rxmraw6h.subclass = 0x1;
            rxmraw6h.length = 0x10;
            rxmraw6h.flags = 0;
            rxmraw6h.startaddr = 0x40F4;
            rxmraw6h.data = new byte[] { 0xe7, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x10 };

            downloadreq rxmsfrb6h = new downloadreq();
            rxmsfrb6h.clas = 0x9;
            rxmsfrb6h.subclass = 0x1;
            rxmsfrb6h.length = 0x10;
            rxmsfrb6h.flags = 0;
            rxmsfrb6h.startaddr = 0x4360;
            rxmsfrb6h.data = new byte[] { 0xd3, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x11 };

            byte[] turnonbytes = new byte[] { 0,1,0,0,0,0,0,0 };

            byte[] header = new byte[] { 0xb5, 0x62 };

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
            //turnon(port, header, 2, 0x53);

            //writepacket(port.BaseStream, header, rxmraw);
            //writepacket(port.BaseStream, header, rxmsfrb);
           
           //writepacket(port.BaseStream, header, rxmraw6h);
           //writepacket(port.BaseStream, header, rxmsfrb6h);


           //turnon(port.BaseStream, header, 2, 0x10);
           //turnon(port.BaseStream, header, 2, 0x11);

           //testmsg.startaddr += 8;
           //testmsg.data = turnonbytes;
           //writepacket(port.BaseStream, header, testmsg);




           // System.Threading.Thread.Sleep(200);

           // while (port.IsOpen)
            {

                while (port.BytesToRead > 0)
                {
                    byte data = (byte)port.ReadByte();

                    // Console.Write("{0,2:x}",data);

                    processbyte(data);
                }

            }

         //   port.Close();

           // Console.ReadLine();

          //  return;

            req = new uploadreq();
            req.clas = 0x9;
            req.subclass = 0x2;
            req.length = 12;
            req.startaddr = 0;
            req.datasize = 64;
            req.flags = 0;

            while (port.IsOpen)
            {
                byte[] datastruct = StaticUtils.StructureToByteArray(req);

                byte[] checksum = ubx_checksum(datastruct, datastruct.Length);

                port.Write(header, 0, header.Length);
                port.Write(datastruct, 0, datastruct.Length);
                port.Write(checksum,0,checksum.Length);

                System.Threading.Thread.Sleep(20);

               // Console.WriteLine("btr " + port.BytesToRead  + " " + port.BytesToWrite);

                while (port.BytesToRead > 0)
                {
                    byte data = (byte)port.ReadByte();

                   // Console.Write("{0,2:x}",data);

                    processbyte(data);
                    
                }
            }
            
        }

        static void writepacket(Stream port, byte[] header, object data)
        {
            byte[] datastruct1 = StaticUtils.StructureToByteArray(data);

            byte[] checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);

            byte[] all = new byte[header.Length + datastruct1.Length + checksum1.Length];

            Array.Copy(header, 0, all, 0, header.Length);
            Array.Copy(datastruct1, 0, all, 2, datastruct1.Length);
            Array.Copy(checksum1, 0, all, all.Length-2, checksum1.Length);

            for (int a = 0; a < all.Length; a++)
            {
                Console.Write(" "+all[a].ToString("X"));
            }
            Console.WriteLine();
        }

        static void processbyte(byte data)
        {
            switch (UBX_step)     //Normally we start from zero. This is a state machine
            {
                case 0:
                    if (data == 0xB5)  // UBX sync char 1
                        UBX_step++;   //OH first data packet is correct, so jump to the next step
                    break;
                case 1:
                    if (data == 0x62)  // UBX sync char 2
                        UBX_step++;   //ooh! The second data packet is correct, jump to the step 2
                    else
                        UBX_step = 0;   //Nop, is not correct so restart to step zero and try again.     
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
                        UBX_step = 0;   //Bad data, so restart to step zero and try again.     
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
                case 6:         // Payload data read...
                    if (UBX_payload_counter < UBX_payload_length_hi)  // We stay in this state until we reach the payload_length
                    {
                        UBX_buffer[UBX_payload_counter] = data;
                        ubx_checksum(data);
                        UBX_payload_counter++;
                        if (UBX_payload_counter == UBX_payload_length_hi)
                            UBX_step++;
                    }
                    break;
                case 7:
                    UBX_ck_a = data;   // First checksum byte
                    UBX_step++;
                    break;
                case 8:
                    UBX_ck_b = data;   // Second checksum byte

                    // We end the GPS read...
                    if ((ck_a == UBX_ck_a) && (ck_b == UBX_ck_b))
                    {  // Verify the received checksum with the generated checksum.. 
                        // Parse the new GPS packet
                        

                        if (UBX_class == 0x9 && UBX_id == 0x2)
                        {
                            uploadresp resp = UBX_buffer.ByteArrayToStructure<uploadresp>(0);

                            Console.WriteLine("{0:X}", resp.startaddr);

                            bw.Seek((int)resp.startaddr, SeekOrigin.Begin);
                            bw.Write(resp.data, 0, (int)req.datasize);

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
                            Console.WriteLine(DateTime.Now + "we have a packet 0x" + UBX_class.ToString("X") + " 0x" + UBX_id.ToString("X") + " " + UBX_payload_counter); 
                        }
                    }
                    else
                    {

                    }
                    // Variable initialization
                    UBX_step = 0;
                    ck_a = 0;
                    ck_b = 0;

                    break;
            }
        }

        static void ubx_checksum(byte ubx_data)
{
  ck_a+=ubx_data;
  ck_b+=ck_a; 
}

        static byte[] ubx_checksum(byte[] packet, int size)
        {
            uint a = 0x00;
            uint b = 0x00;
            int i = 0;
            while (i < size)
            {
                a += packet[i++];
                b += a;
            }

            byte[] ans = new byte[2];

            ans[0] = (byte)(a & 0xFF);
            ans[1] = (byte)(b & 0xFF);

            return ans;
        }
    }
}

