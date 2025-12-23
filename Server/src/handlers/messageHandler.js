// ============================================
// File: src/handlers/messageHandler.js
// ============================================

export class MessageHandler {
  constructor() {
    // Predefined responses for quick commands
    this.commandResponses = {
      'name': 'My name is SecureBot 🤖',
      'age': 'I am timeless - created in 2025 ⏳',
      'time': () => {
        const now = new Date();
        return `Current server time: ${now.toLocaleString('en-US', { 
          timeZone: 'UTC',
          hour12: true,
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        })} UTC 🕐`;
      },
      'status': () => {
        return `✅ System Status: Online\n📊 Encryption: Active\n🔐 Algorithm: ECDH-P192\n⏱️ Uptime: ${this.getUptime()}`;
      },
      'help': 'Available commands:\n• name - Get bot name\n• age - Get bot age\n• time - Get server time\n• status - Get system status\n• help - Show this help',
      'hello': 'Hello! 👋 How can I help you today?',
      'hi': 'Hi there! 👋',
      'ping': 'Pong! 🏓',
      'test': 'Test successful! All systems operational ✅'
    };
    
    this.startTime = Date.now();
  }

  // Get system uptime
  getUptime() {
    const uptime = Date.now() - this.startTime;
    const seconds = Math.floor(uptime / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  // Process incoming message
  processMessage(message) {
    const lowerMessage = message.toLowerCase().trim();
    
    // Check for command
    if (this.commandResponses.hasOwnProperty(lowerMessage)) {
      const response = this.commandResponses[lowerMessage];
      return typeof response === 'function' ? response() : response;
    }
    
    // Check for patterns
    if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
      return 'Hello! 👋 Nice to meet you!';
    }
    
    if (lowerMessage.includes('how are you')) {
      return 'I\'m doing great! Thanks for asking! 😊';
    }
    
    if (lowerMessage.includes('thanks') || lowerMessage.includes('thank you')) {
      return 'You\'re welcome! 😊';
    }
    
    // Default echo response
    return `Server does not understand: ${message} ✅`;
  }

  // Get available commands
  getAvailableCommands() {
    return Object.keys(this.commandResponses);
  }
}