using Microsoft.AspNetCore.SignalR;
using WirePeek.Models;

namespace WirePeek.Hubs;

/// <summary>SignalR hub that pushes live capture updates to connected browsers.</summary>
public sealed class CaptureHub : Hub
{
}

public interface ICaptureBroadcaster
{
    Task NewSessionAsync(SessionSummary summary);
    Task UpdateSessionAsync(SessionSummary summary);
    Task ClearedAsync();
}

public sealed class CaptureBroadcaster : ICaptureBroadcaster
{
    private readonly IHubContext<CaptureHub> _hub;
    public CaptureBroadcaster(IHubContext<CaptureHub> hub) => _hub = hub;

    public Task NewSessionAsync(SessionSummary summary) =>
        _hub.Clients.All.SendAsync("newSession", summary);

    public Task UpdateSessionAsync(SessionSummary summary) =>
        _hub.Clients.All.SendAsync("updateSession", summary);

    public Task ClearedAsync() =>
        _hub.Clients.All.SendAsync("cleared");
}
