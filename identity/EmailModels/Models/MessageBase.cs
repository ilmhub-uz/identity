using identity.EmailModels.Enums;

namespace identity.EmailModels.Models;

public class MessageBase
{
    public string SenderService { get; set; }
    public EMessageType Type { get; set; }
    public EMessageStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public MessageBase(string senderService, EMessageType type)
    {
        CreatedAt = DateTimeOffset.UtcNow;
        Status = EMessageStatus.Created;
        SenderService = senderService;
        Type = type;
    }
}