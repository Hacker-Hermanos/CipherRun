using System.Threading;
using System;

namespace Heuristics
{
	public static class Heuristics
	{
		public static bool Sleep()
		{
			DateTime t1 = DateTime.Now;

			Thread.Sleep(5000);
			double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
			
			if (t2 < 1.5)
			{
				return true;
			} else
            {
				return false;
            }
		}
	}
}
