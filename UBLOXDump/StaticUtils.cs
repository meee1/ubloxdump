using System;
using System.Runtime.InteropServices;

internal static class StaticUtils
{
    public static TPacket ByteArrayToStructure<TPacket>(this byte[] bytearray, int startoffset) where TPacket : struct
    {
        object newPacket = new TPacket();
        ByteArrayToStructure(bytearray, ref newPacket, startoffset);
        return (TPacket) newPacket;
    }

    public static void ByteArrayToStructure(byte[] bytearray, ref object obj, int startoffset)
    {
        var len = Marshal.SizeOf(obj);

        var i = Marshal.AllocHGlobal(len);

        // create structure from ptr
        obj = Marshal.PtrToStructure(i, obj.GetType());

        try
        {
            // copy byte array to ptr
            Marshal.Copy(bytearray, startoffset, i, len);
        }
        catch (Exception ex)
        {
            Console.WriteLine("ByteArrayToStructure FAIL " + ex.Message);
        }

        obj = Marshal.PtrToStructure(i, obj.GetType());

        Marshal.FreeHGlobal(i);
    }

    public static void ByteArrayToStructureEndian(byte[] bytearray, ref object obj, int startoffset)
    {
        var len = Marshal.SizeOf(obj);
        var i = Marshal.AllocHGlobal(len);
        var temparray = (byte[]) bytearray.Clone();

        // create structure from ptr
        obj = Marshal.PtrToStructure(i, obj.GetType());

        // do endian swap
        var thisBoxed = obj;
        var test = thisBoxed.GetType();

        var reversestartoffset = startoffset;

        // Enumerate each structure field using reflection.
        foreach (var field in test.GetFields())
        {
            // field.Name has the field's name.
            var fieldValue = field.GetValue(thisBoxed); // Get value

            // Get the TypeCode enumeration. Multiple types get mapped to a common typecode.
            var typeCode = Type.GetTypeCode(fieldValue.GetType());

            if (typeCode != TypeCode.Object)
            {
                Array.Reverse(temparray, reversestartoffset, Marshal.SizeOf(fieldValue));
                reversestartoffset += Marshal.SizeOf(fieldValue);
            }
            else
            {
                reversestartoffset += ((byte[]) fieldValue).Length;
            }
        }

        try
        {
            // copy byte array to ptr
            Marshal.Copy(temparray, startoffset, i, len);
        }
        catch (Exception ex)
        {
            Console.WriteLine("ByteArrayToStructure FAIL" + ex);
        }

        obj = Marshal.PtrToStructure(i, obj.GetType());

        Marshal.FreeHGlobal(i);
    }

    public static byte[] StructureToByteArray(object obj)
    {
        var len = Marshal.SizeOf(obj);
        var arr = new byte[len];
        var ptr = Marshal.AllocHGlobal(len);
        Marshal.StructureToPtr(obj, ptr, true);
        Marshal.Copy(ptr, arr, 0, len);
        Marshal.FreeHGlobal(ptr);
        return arr;
    }
}