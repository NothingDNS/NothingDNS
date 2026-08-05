import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorBoundary } from './error-boundary';

// A child component that throws on render
function CrashChild({ shouldCrash = false }: { shouldCrash?: boolean }) {
  if (shouldCrash) throw new Error('Boom!');
  return <p>All good</p>;
}

// A child that throws an error with empty message
function EmptyMessageCrash(): never {
  throw new Error('');
}

// Suppress console.error from React error boundary logging during tests
vi.spyOn(console, 'error').mockImplementation(() => {});

describe('ErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <p>Hello world</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText('Hello world')).toBeInTheDocument();
  });

  it('renders fallback UI on child error', () => {
    render(
      <ErrorBoundary>
        <CrashChild shouldCrash />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Try again')).toBeInTheDocument();
  });

  it('shows the error message in fallback', () => {
    render(
      <ErrorBoundary>
        <CrashChild shouldCrash />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Boom!')).toBeInTheDocument();
  });

  it('self-heals when resetKey changes', async () => {
    const { rerender } = render(
      <ErrorBoundary resetKey="page-1">
        <CrashChild shouldCrash />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();

    // Rerender with different resetKey and a non-crashing child
    rerender(
      <ErrorBoundary resetKey="page-2">
        <p>Recovered</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText('Recovered')).toBeInTheDocument();
  });

  it('"Try again" button resets error state and allows recovery with new child', async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <ErrorBoundary resetKey="same">
        <CrashChild shouldCrash />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();

    // Click "Try again" — error is cleared, but the same child still crashes
    await user.click(screen.getByText('Try again'));

    // After clicking Try again, the error resets then the child re-renders
    // and crashes again. The fallback should reappear.
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();

    // Now rerender with a different resetKey and non-crashing child to prove
    // the boundary can fully recover
    rerender(
      <ErrorBoundary resetKey="recovered">
        <p>After recovery</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText('After recovery')).toBeInTheDocument();
  });

  it('shows fallback message when error has no message', () => {
    render(
      <ErrorBoundary>
        <EmptyMessageCrash />
      </ErrorBoundary>,
    );
    expect(
      screen.getByText('An unexpected error occurred while rendering this page.'),
    ).toBeInTheDocument();
  });
});
