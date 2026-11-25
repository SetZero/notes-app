// The link between classes and React.
//
// State and behaviour of every screen live in a view-model class. A React
// function component only renders the current state and forwards user input:
//
//     const state = useViewModel(editor);
//     <input value={state.title} onChange={(e) => editor.setTitle(e.target.value)} />
//
// React re-renders the component whenever the view model replaces its state.

import { useSyncExternalStore } from "react";

export abstract class ViewModel<State extends object> {
  private readonly listeners = new Set<() => void>();
  private current: State;

  protected constructor(initial: State) {
    this.current = initial;
  }

  /** The current state. A new object after every change, never mutated. */
  public get state(): State {
    return this.current;
  }

  // Arrow functions, because React calls these without `this`.
  public readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  public readonly snapshot = (): State => this.current;

  protected setState(patch: Partial<State>): void {
    this.current = { ...this.current, ...patch };
    for (const listener of [...this.listeners]) listener();
  }
}

export function useViewModel<State extends object>(viewModel: ViewModel<State>): State {
  return useSyncExternalStore(viewModel.subscribe, viewModel.snapshot);
}
