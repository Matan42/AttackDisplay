import { createChatBotMessage } from 'react-chatbot-kit';
import Chatbot from 'react-chatbot-kit';
import { API_BASE } from './constants/api';
import './BotTab.css';

class ActionProvider {
  constructor(createChatBotMessage, setState) {
    this.createChatBotMessage = createChatBotMessage;
    this.setState = setState;
  }

  addMessage = (message, isBot = true) => {
    const botMessage = this.createChatBotMessage(message);
    this.setState((prev) => ({ ...prev, messages: [...prev.messages, botMessage] }));
  };

  sendMessageToBot = async (userMessage) => {
    try {
      const response = await fetch(`${API_BASE}/bot/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage })
      });

      const data = await response.json();
      if (data.success && data.response) {
        this.addMessage(data.response, true);
      } else {
        this.addMessage('Bot encountered an error processing your request. Please try again.', true);
      }
    } catch (error) {
      console.error('Bot chat error:', error);
      this.addMessage('Failed to communicate with the bot service. Check if the backend is running.', true);
    }
  };
}

class MessageParser {
  constructor(actionProvider) {
    this.actionProvider = actionProvider;
  }

  parse(message) {
    this.actionProvider.sendMessageToBot(message);
  }
}

const config = {
  botName: 'CyberBot',
  initialMessages: [
    createChatBotMessage(
      'Hello, I am CyberBot. I can help you search for ATT&CK techniques, check file hashes against VirusTotal, and manage sandbox analysis tasks.'
    ),
  ],
  customStyles: {
    botMessageBox: {
      backgroundColor: '#171722',
      color: '#f5f5f5',
      fontSize: '14px',
    },
    chatButton: {
      backgroundColor: '#dc1f2e',
      color: '#ffffff',
    },
  },
};

export default function BotTab() {
  return (
    <div className="bot-tab-shell">
      <div className="bot-panel">
        <div className="bot-intro">
          <div className="bot-header-row">
            <h1>Cyber Bot</h1>
            <p>This chat helps the analyst search techniques, check file hashes, and manage sandbox investigations.</p>
          </div>

          <div className="bot-hint-list">
            <span className="bot-hint">search DLL</span>
            <span className="bot-hint">find execution</span>
            <span className="bot-hint">check md5 5d41402abc4b2a76b9719d911017c592</span>
            <span className="bot-hint">sandbox analyze malware.exe</span>
            <span className="bot-hint">sandbox status 1</span>
          </div>
        </div>

        <Chatbot
          config={config}
          messageParser={MessageParser}
          actionProvider={ActionProvider}
        />
      </div>
    </div>
  );
}
