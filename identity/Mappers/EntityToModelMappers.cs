namespace identity.Mappers;

public static class EntitiyToModelMappers
{
    public static ilmhub.model.Message ToModel(this ilmhub.entity.Message msg)
    {
        return new ilmhub.model.Message(msg.SenderService, msg.Type, msg.FromEmail, msg.FromName, msg.ToEmail, msg.ToName, msg.Subject, msg.TextContent, msg.HtmlContent);
    }
}