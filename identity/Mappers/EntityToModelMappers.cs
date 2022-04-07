namespace identity.Mappers;

public static class EntitiyToModelMappers
{
    public static identity.EmailModels.Models.Message ToModel(this identity.EmailModels.Entity.Message msg)
    {
        return new identity.EmailModels.Models.Message(msg.SenderService, msg.Type, msg.FromEmail, msg.FromName, msg.ToEmail, msg.ToName, msg.Subject, msg.TextContent, msg.HtmlContent);
    }
}