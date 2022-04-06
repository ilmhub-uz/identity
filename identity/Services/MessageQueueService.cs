using identity.Data;
using SendGrid;
using Microsoft.EntityFrameworkCore;
using SendGrid.Helpers.Mail;
using identity.EmailModels.Enums;

namespace identity.Services;
public class MessageQueueService : BackgroundService
{
    private const int MAX_RETRY_COUNT = 3;
    private const int EMPTY_QUEUE_DELAY_IN_SECONDS = 60 * 3;
    private readonly ILogger<MessageQueueService> _logger;
    private readonly ISendGridClient _client;
    private readonly MessageQueue<KeyValuePair<Guid, identity.EmailModels.Models.Message>> _queue;
    private readonly IServiceScopeFactory _scopeFactory;

    public MessageQueueService(ILogger<MessageQueueService> logger, ISendGridClient client, MessageQueue<KeyValuePair<Guid, identity.EmailModels.Models.Message>> queue, IServiceScopeFactory scopeFactory)
    {
        _logger = logger;
        _client = client;
        _queue = queue;
        _scopeFactory = scopeFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while(!stoppingToken.IsCancellationRequested)
        {
            var message = await _queue.DequeueAsync(stoppingToken);
            if(message.Value is null)
            {
                await Task.Delay(TimeSpan.FromSeconds(EMPTY_QUEUE_DELAY_IN_SECONDS), stoppingToken);
                continue;
            }

            using var scope = _scopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var msg = await context.Messages.FirstOrDefaultAsync(m => m.Id == message.Key, cancellationToken: stoppingToken);
            if(msg is null)
            {
                _logger.LogError("There is no message with given ID: ", message.Key);
                continue;
            }

            if(msg.RetryCount >= MAX_RETRY_COUNT)
            {
                _logger.LogWarning("There is no message with given ID: ", message.Key);
                continue;
            }

            var from = new EmailAddress(msg.FromEmail, msg.FromName);
            var to = new EmailAddress(msg.ToEmail, msg.ToName);
            var email = MailHelper.CreateSingleEmail(from, to, msg.Subject, msg.TextContent, msg.HtmlContent);

            var response = await _client.SendEmailAsync(email, stoppingToken);
            if(!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Email delivery failed: ", msg.Id);
                msg.Status = EMessageStatus.Failed;
            }
            else
            {
                _logger.LogInformation("Email delivery success: ", msg.Id);
                msg.Status = EMessageStatus.Delivered;
            }

            msg.RetryCount++;
            context.Messages.Update(msg);
            await context.SaveChangesAsync(stoppingToken);
        }
    }
}