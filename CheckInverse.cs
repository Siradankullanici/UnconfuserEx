using System;

class Program
{
    static void Main()
    {
        uint key = 0x2B9F8B98;
        uint storedHash = 0xFD2431DD;
        
        Console.WriteLine($"Key: {key:X8}");
        Console.WriteLine($"Stored Hash: {storedHash:X8}");
        
        // Direct multiplication
        uint direct = key * storedHash;
        Console.WriteLine($"Direct (Key * Stored): {direct:X8}");
        
        // Inverse multiplication
        uint inv = ModInverse(storedHash);
        uint inverseCalc = key * inv;
        Console.WriteLine($"Inverse of Stored: {inv:X8}");
        Console.WriteLine($"Inverse Calc (Key * Inv): {inverseCalc:X8}");
    }
    
    static uint ModInverse(uint n)
    {
        long x = n;
        long y = 0x100000000;
        long n0 = y;
        long a = 0, b = 1;
        long t, q;
        
        if (y == 1) return 0;
        
        while (x > 1)
        {
            // q is quotient
            q = x / y;
            t = y;
            
            // m is remainder now, process same as euclidean algo
            y = x % y;
            x = t;
            t = a;
            
            // Update a and b
            a = b - q * a;
            b = t;
        }
        
        if (b < 0) b += n0;
        
        return (uint)b;
    }
}
