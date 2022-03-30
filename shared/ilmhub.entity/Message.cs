using System.ComponentModel.DataAnnotations;
using ilmhub.core;

namespace ilmhub.entity;

public class Message
{
    [Key]
    public Guid Id { get; set; }
    public string SenderService { get; set; }
    public EMessageType Type { get; set; }
    public EMessageStatus Status { get; set; }
    public string FromEmail { get; set; }
    public string FromName { get; set; }
    public string ToEmail { get; set; }
    public string ToName { get; set; }
    public string Subject { get; set; }
    public string TextContent { get; set; }
    public string HtmlContent { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public int RetryCount { get; set; }
    
    [Obsolete("Used only for entity binding.")]
    public Message() { }

    public Message(string senderService, EMessageType type, string fromEmail, string fromName, string toEmail, string toName, string subject, string textContent, string htmlContent)
    {
        Id = Guid.NewGuid();
        SenderService = senderService;
        Type = type;
        Status = EMessageStatus.Created;
        FromEmail = fromEmail;
        FromName = fromName;
        ToEmail = toEmail;
        ToName = toName;
        Subject = subject;
        TextContent = textContent;
        HtmlContent = htmlContent;
        CreatedAt = DateTimeOffset.UtcNow;
        RetryCount = 0;
    }
}