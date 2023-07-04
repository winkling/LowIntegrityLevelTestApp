namespace LowIntegrityLevelTestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            NativeMethods.CreateLowProcess(@"C:\Windows\System32\notepad.exe");
        }
    }
}
