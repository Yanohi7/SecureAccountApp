using System.Net;
using System.Net.Mail;

namespace Backend.Services;

public class EmailService(IConfiguration configuration, ILogger<EmailService> logger)
{
    private string FrontendUrl => (configuration["FrontendOrigin"] ?? "http://localhost:5173").TrimEnd('/');

    public Task SendActivationEmailAsync(string email, string token) =>
        SendAsync(email, "Активація облікового запису",
            $"Для активації облікового запису перейдіть за посиланням:\n{FrontendUrl}/?token={token}\n\nПосилання дійсне 24 години.");

    public Task SendPasswordResetEmailAsync(string email, string token) =>
        SendAsync(email, "Відновлення пароля",
            $"Для встановлення нового пароля перейдіть за посиланням:\n{FrontendUrl}/?resetToken={token}\n\nПосилання дійсне 1 годину. Якщо ви не надсилали запит, проігноруйте лист.");

    public Task SendTwoFactorCodeEmailAsync(string email, string code) =>
        SendAsync(email, "Код двоетапної перевірки",
            $"Ваш одноразовий код для входу:\n{code}\n\nКод дійсний 5 хвилин.");

    private async Task SendAsync(string email, string subject, string body)
    {
        var settings = configuration.GetSection("SmtpSettings");
        var sender = settings["SenderEmail"] ?? throw new InvalidOperationException("Missing SMTP sender.");
        var server = settings["Server"] ?? throw new InvalidOperationException("Missing SMTP server.");
        using var message = new MailMessage(new MailAddress(sender, settings["SenderName"]), new MailAddress(email))
        {
            Subject = subject,
            Body = body
        };
        using var client = new SmtpClient(server, settings.GetValue("Port", 587))
        {
            EnableSsl = true
        };

        if (!string.IsNullOrEmpty(settings["Password"]))
            client.Credentials = new NetworkCredential(sender, settings["Password"]);

        try
        {
            await client.SendMailAsync(message);
        }
        catch (SmtpException ex)
        {
            logger.LogWarning(ex, "SMTP delivery failed.");
            throw;
        }
    }
}
