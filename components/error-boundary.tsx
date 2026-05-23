'use client';

import React, { ReactNode, ErrorInfo } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
  errorInfo?: ErrorInfo;
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    this.setState({ errorInfo });
    
    // Log to external service in production
    if (typeof window !== 'undefined' && process.env.NODE_ENV === 'production') {
      // Could send to error tracking service like Sentry
      console.error('Error logged for monitoring:', {
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
      });
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div className="flex items-center justify-center min-h-screen bg-slate-950">
            <div className="max-w-md w-full mx-4 p-6 bg-slate-900 border border-red-500/30 rounded-lg shadow-lg">
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="w-6 h-6 text-red-400" />
                <h1 className="text-xl font-bold text-red-400">Something went wrong</h1>
              </div>
              
              <p className="text-sm text-gray-400 mb-4">
                An unexpected error occurred. The error has been logged and our team will investigate.
              </p>

              {process.env.NODE_ENV === 'development' && this.state.error && (
                <div className="mb-4 p-3 bg-slate-800 rounded border border-red-500/20">
                  <p className="text-xs font-mono text-red-300 break-words">
                    {this.state.error.message}
                  </p>
                  {this.state.errorInfo && (
                    <details className="mt-2">
                      <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-300">
                        Stack trace
                      </summary>
                      <pre className="mt-2 text-xs text-gray-500 overflow-auto max-h-40">
                        {this.state.errorInfo.componentStack}
                      </pre>
                    </details>
                  )}
                </div>
              )}

              <div className="flex gap-2">
                <button
                  onClick={this.handleReset}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium transition-colors"
                >
                  <RotateCcw className="w-4 h-4" />
                  Try Again
                </button>
                <button
                  onClick={() => window.location.href = '/'}
                  className="flex-1 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-gray-200 rounded font-medium transition-colors"
                >
                  Go Home
                </button>
              </div>
            </div>
          </div>
        )
      );
    }

    return this.props.children;
  }
}
