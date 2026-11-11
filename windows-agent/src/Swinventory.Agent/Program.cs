using System.Text;
using Swinventory.Agent;

Console.OutputEncoding = new UTF8Encoding(false);   // print 출력의 한글이 깨지지 않게(BOM 없이)
return Cli.Run(args, CliRuntime.Default());
