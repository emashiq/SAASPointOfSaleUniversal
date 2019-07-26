﻿using System.Threading.Tasks;

namespace WebApp.Mailing
{
    public interface IEmailSender
    {
        string UserId { get; set; }

        string Token { get; set; }

        Task SendMailConfirmationLink(string userId, string token);

        Task SendMailPasswordReset(string userId, string token);
    }
}
