namespace LowIntegrityLevelTestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            NativeMethods.CreateLowProcess(@"C:\Storage\Code-p\GrpcGreeter\GrpcGreeterClient\bin\Debug\net6.0\GrpcGreeterClient.exe");
        }
    }
}