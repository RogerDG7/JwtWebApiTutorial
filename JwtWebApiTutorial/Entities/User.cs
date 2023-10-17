using System;
namespace JwtWebApiTutorial.Entities
{
	public class User
	{
		public string UserName { get; set; } = string.Empty;
		public byte[] PassWordHash { get; set; }
		public byte[] PassWordSalt { get; set; }

		public string RefreshToken { get; set; } = string.Empty;
		public DateTime TokenCreated { get; set; }
		public DateTime TokenExpires { get; set; }
	}
}

