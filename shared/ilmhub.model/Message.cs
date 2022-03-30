using ilmhub.core;

namespace ilmhub.model;

public class Message : MessageBase
{
    public string FromEmail { get; set; }
    public string FromName { get; set; }
    public string ToEmail { get; set; }
    public string ToName { get; set; }
    public string Subject { get; set; }
    public string TextContent { get; set; }
    public string HtmlContent { get; set; }

    public Message(string senderService, EMessageType type, string fromEmail, string fromName, string toEmail, string toName, string subject, string textContent, string htmlContent)
        : base(senderService, type)
    {
        FromEmail = fromEmail;
        FromName = fromName;
        ToEmail = toEmail;
        ToName = toName;
        Subject = subject;
        TextContent = textContent;
        HtmlContent = htmlContent;
    }
}