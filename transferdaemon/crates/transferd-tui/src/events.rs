use crate::app::*;
use crate::types::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Returns `true` when the app should quit.
pub async fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    // Global: Ctrl+Q always quits (unless modal captures it).
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('q') {
        return true;
    }

    // ── Onboarding ───────────────────────────────────────────────────────────
    if let Screen::Onboarding(step) = app.screen.clone() {
        return handle_onboarding(app, key, &step).await;
    }

    // ── Call overlay shortcuts (available everywhere) ─────────────────────
    if app.call_state.is_some() {
        match key.code {
            KeyCode::Char('m') | KeyCode::Char('M') => {
                if let Some(cs) = &mut app.call_state { cs.muted = !cs.muted; }
                return false;
            }
            KeyCode::Char('h') | KeyCode::Char('H') => {
                if let Some(cs) = app.call_state.take() {
                    let _ = app.daemon.end_call(&cs.call_id).await;
                    app.set_status("Call ended.");
                }
                return false;
            }
            // Toggle video overlay visibility.
            KeyCode::Char('v') | KeyCode::Char('V') => {
                if let Some(cs) = &mut app.call_state {
                    if cs.video.is_some() {
                        cs.video = None;
                        app.set_status("Video hidden. [V] show again");
                    } else if cs.video_enabled {
                        cs.video = Some(transferd_tui_video::VideoCallOverlay::new(cs.contact_name.clone()));
                        app.set_status("Video shown.");
                    }
                }
                return false;
            }
            _ => {}
        }
    }

    // ── Modal ────────────────────────────────────────────────────────────────
    if app.modal.is_some() {
        return handle_modal(app, key).await;
    }

    // ── Global tab switching ─────────────────────────────────────────────────
    match key.code {
        KeyCode::F(1) => { app.tab = Tab::Chats;     app.set_status(""); return false; }
        KeyCode::F(2) => { app.tab = Tab::Contacts;  app.set_status(""); return false; }
        KeyCode::F(3) => { app.tab = Tab::Transfers; app.set_status(""); return false; }
        KeyCode::F(4) => { app.tab = Tab::Settings;  app.set_status(""); return false; }
        _ => {}
    }

    // ── Per-tab ──────────────────────────────────────────────────────────────
    match app.tab {
        Tab::Chats     => handle_chats(app, key).await,
        Tab::Contacts  => handle_contacts(app, key).await,
        Tab::Transfers => handle_transfers(app, key).await,
        Tab::Settings  => handle_settings(app, key).await,
    }

    false
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

async fn handle_onboarding(app: &mut App, key: KeyEvent, step: &OnboardingStep) -> bool {
    match step {
        OnboardingStep::Welcome => match key.code {
            KeyCode::Char('1') => {
                app.input.clear();
                app.screen = Screen::Onboarding(OnboardingStep::EnterName);
            }
            KeyCode::Char('2') => {
                app.input.clear();
                app.screen = Screen::Onboarding(OnboardingStep::EnterPhrase);
            }
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        },

        OnboardingStep::EnterName => match key.code {
            KeyCode::Enter => {
                let name = app.input.trim().to_owned();
                let display_name = if name.is_empty() { "Anonymous".to_owned() } else { name };
                match app.daemon.create_identity(display_name).await {
                    Ok(phrase) => {
                        app.identity = app.daemon.get_identity().await;
                        app.recovery_phrase = Some(phrase.clone());
                        app.input.clear();
                        app.screen = Screen::Onboarding(OnboardingStep::ShowPhrase { phrase });
                    }
                    Err(e) => app.set_status(format!("Error: {}", e)),
                }
            }
            KeyCode::Esc => {
                app.input.clear();
                app.screen = Screen::Onboarding(OnboardingStep::Welcome);
            }
            _ => edit_input(&mut app.input, key),
        },

        OnboardingStep::ShowPhrase { phrase } => {
            let phrase = phrase.clone();
            match key.code {
                KeyCode::Enter => {
                    app.input.clear();
                    app.screen = Screen::Onboarding(OnboardingStep::ConfirmPhrase { phrase });
                }
                KeyCode::Esc => {
                    // Cancel account creation; clear identity.
                    app.identity = None;
                    app.recovery_phrase = None;
                    app.input.clear();
                    app.screen = Screen::Onboarding(OnboardingStep::Welcome);
                }
                _ => {}
            }
        }

        OnboardingStep::ConfirmPhrase { phrase } => {
            let phrase = phrase.clone();
            match key.code {
                KeyCode::Enter => {
                    if app.input.trim() == phrase.as_str() {
                        // Confirmed — load contacts and enter main.
                        app.contacts = app.daemon.get_contacts().await;
                        app.transfers = app.daemon.get_transfers().await;
                        app.screen = Screen::Main;
                        app.set_status("Account created. Welcome!");
                    } else {
                        app.set_status("Phrase doesn't match — try again.");
                        app.input.clear();
                    }
                }
                KeyCode::Esc => {
                    app.input.clear();
                    app.screen = Screen::Onboarding(OnboardingStep::ShowPhrase { phrase });
                }
                _ => edit_input(&mut app.input, key),
            }
        }

        OnboardingStep::EnterPhrase => match key.code {
            KeyCode::Enter => {
                let phrase = app.input.trim().to_owned();
                if phrase.split_whitespace().count() < 12 {
                    app.set_status("Need at least 12 words.");
                    return false;
                }
                match app.daemon.restore_identity(phrase).await {
                    Ok(id) => {
                        app.identity = Some(id);
                        app.contacts = app.daemon.get_contacts().await;
                        app.transfers = app.daemon.get_transfers().await;
                        app.screen = Screen::Main;
                        app.set_status("Identity restored. Welcome back!");
                    }
                    Err(e) => app.set_status(format!("Error: {}", e)),
                }
            }
            KeyCode::Esc => {
                app.input.clear();
                app.screen = Screen::Onboarding(OnboardingStep::Welcome);
            }
            _ => edit_input(&mut app.input, key),
        },
    }
    false
}

// ---------------------------------------------------------------------------
// Chats tab
// ---------------------------------------------------------------------------

async fn handle_chats(app: &mut App, key: KeyEvent) {
    // Tab / Shift+Tab cycles focus.
    if key.code == KeyCode::Tab {
        app.chat_focus = match app.chat_focus {
            ChatFocus::ContactList => ChatFocus::Messages,
            ChatFocus::Messages    => ChatFocus::Input,
            ChatFocus::Input       => ChatFocus::ContactList,
        };
        return;
    }
    if key.code == KeyCode::BackTab {
        app.chat_focus = match app.chat_focus {
            ChatFocus::ContactList => ChatFocus::Input,
            ChatFocus::Messages    => ChatFocus::ContactList,
            ChatFocus::Input       => ChatFocus::Messages,
        };
        return;
    }

    match app.chat_focus {
        ChatFocus::ContactList => match key.code {
            KeyCode::Up => {
                if app.selected_contact > 0 { app.selected_contact -= 1; app.msg_scroll = 0; }
            }
            KeyCode::Down => {
                if app.selected_contact + 1 < app.contacts.len() {
                    app.selected_contact += 1;
                    app.msg_scroll = 0;
                    // Lazy-load messages.
                    if let Some(id) = app.open_contact_id().map(|s| s.to_owned()) {
                        if !app.messages.contains_key(&id) {
                            let msgs = app.daemon.get_messages(&id).await;
                            app.messages.insert(id, msgs);
                        }
                    }
                }
            }
            KeyCode::Enter => { app.chat_focus = ChatFocus::Input; }
            _ => {}
        },

        ChatFocus::Messages => match key.code {
            KeyCode::Up => { if app.msg_scroll > 0 { app.msg_scroll -= 1; } }
            KeyCode::Down => { app.msg_scroll += 1; }
            KeyCode::Enter | KeyCode::Char('i') => { app.chat_focus = ChatFocus::Input; }
            _ => {}
        },

        ChatFocus::Input => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                match key.code {
                    KeyCode::Char('f') => {
                        if app.contacts.is_empty() {
                            app.set_status("No contact selected.");
                        } else {
                            app.modal = Some(Modal::SendFile { path_input: String::new() });
                        }
                    }
                    KeyCode::Char('c') => {
                        // Start audio call.
                        app.start_call_to_selected(false).await;
                    }
                    KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Start video call.
                        app.start_call_to_selected(true).await;
                    }
                    KeyCode::Char('n') => {
                        // New conversation → open add-contact modal.
                        app.modal = Some(Modal::AddContact {
                            key_input: String::new(),
                            name_input: String::new(),
                            field: 0,
                        });
                    }
                    _ => {}
                }
                return;
            }

            match key.code {
                KeyCode::Enter => {
                    let text = app.input.trim().to_owned();
                    if text.is_empty() { return; }
                    if let Some(id) = app.open_contact_id().map(|s| s.to_owned()) {
                        match app.daemon.send_text(&id, text).await {
                            Ok(msg) => {
                                app.messages.entry(id).or_default().push(msg);
                                app.input.clear();
                                // Scroll to bottom.
                                app.msg_scroll = app.open_messages().len().saturating_sub(1);
                            }
                            Err(e) => app.set_status(format!("Send failed: {}", e)),
                        }
                    } else {
                        app.set_status("No contact selected.");
                    }
                }
                KeyCode::Esc => { app.chat_focus = ChatFocus::ContactList; }
                _ => edit_input(&mut app.input, key),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Contacts tab
// ---------------------------------------------------------------------------

async fn handle_contacts(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up => {
            if app.contacts_selected > 0 { app.contacts_selected -= 1; }
        }
        KeyCode::Down => {
            if app.contacts_selected + 1 < app.contacts.len() { app.contacts_selected += 1; }
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app.modal = Some(Modal::AddContact {
                key_input: String::new(),
                name_input: String::new(),
                field: 0,
            });
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            if let Some(c) = app.contacts.get(app.contacts_selected) {
                app.modal = Some(Modal::ConfirmDelete {
                    label: c.name.clone(),
                    contact_id: c.id.clone(),
                });
            }
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if let Some(c) = app.contacts.get(app.contacts_selected) {
                app.modal = Some(Modal::ShowQr { hex: c.id.clone() });
            }
        }
        KeyCode::Enter => {
            // Open chat with selected contact.
            app.selected_contact = app.contacts_selected;
            app.tab = Tab::Chats;
            app.chat_focus = ChatFocus::Input;
            if let Some(id) = app.open_contact_id().map(|s| s.to_owned()) {
                if !app.messages.contains_key(&id) {
                    let msgs = app.daemon.get_messages(&id).await;
                    app.messages.insert(id, msgs);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Transfers tab
// ---------------------------------------------------------------------------

async fn handle_transfers(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up   => { if app.transfers_selected > 0 { app.transfers_selected -= 1; } }
        KeyCode::Down => { if app.transfers_selected + 1 < app.transfers.len() { app.transfers_selected += 1; } }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            if let Some(t) = app.transfers.get(app.transfers_selected) {
                let id = t.id.clone();
                app.transfers.retain(|t| t.id != id);
                app.clamp_transfers_sel();
                app.set_status("Transfer cancelled.");
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Settings tab
// ---------------------------------------------------------------------------

async fn handle_settings(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if let Some(phrase) = &app.recovery_phrase {
                app.modal = Some(Modal::RevealPhrase { phrase: phrase.clone() });
            } else {
                app.set_status("Recovery phrase not available in this session.");
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Modal handler
// ---------------------------------------------------------------------------

async fn handle_modal(app: &mut App, key: KeyEvent) -> bool {
    let modal = match app.modal.take() {
        Some(m) => m,
        None => return false,
    };

    match modal {
        Modal::AddContact { mut key_input, mut name_input, mut field } => {
            match key.code {
                KeyCode::Esc => { /* modal closed, already taken */ }
                KeyCode::Tab => {
                    field = 1 - field;
                    app.modal = Some(Modal::AddContact { key_input, name_input, field });
                }
                KeyCode::Enter => {
                    if field == 0 {
                        field = 1;
                        app.modal = Some(Modal::AddContact { key_input, name_input, field });
                    } else {
                        // Submit.
                        let name = if name_input.trim().is_empty() { "Unknown".to_owned() } else { name_input.trim().to_owned() };
                        match app.daemon.add_contact(key_input.trim().to_owned(), name).await {
                            Ok(c) => {
                                app.contacts.push(c);
                                app.set_status("Contact added.");
                            }
                            Err(e) => {
                                app.set_status(format!("Error: {}", e));
                                app.modal = Some(Modal::AddContact {
                                    key_input: key_input.trim().to_owned(),
                                    name_input,
                                    field,
                                });
                            }
                        }
                    }
                }
                _ => {
                    if field == 0 { edit_input(&mut key_input, key); }
                    else          { edit_input(&mut name_input, key); }
                    app.modal = Some(Modal::AddContact { key_input, name_input, field });
                }
            }
        }

        Modal::SendFile { mut path_input } => {
            match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let path = path_input.trim().to_owned();
                    if let Some(id) = app.open_contact_id().map(|s| s.to_owned()) {
                        match app.daemon.send_file(&id, path).await {
                            Ok(msg) => {
                                app.messages.entry(id.clone()).or_default().push(msg);
                                app.transfers = app.daemon.get_transfers().await;
                                app.set_status("File transfer started.");
                            }
                            Err(e) => {
                                app.set_status(format!("Error: {}", e));
                                app.modal = Some(Modal::SendFile { path_input });
                            }
                        }
                    }
                }
                _ => {
                    edit_input(&mut path_input, key);
                    app.modal = Some(Modal::SendFile { path_input });
                }
            }
        }

        Modal::ConfirmDelete { label, contact_id } => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let _ = app.daemon.remove_contact(contact_id.clone()).await;
                    app.contacts.retain(|c| c.id != contact_id);
                    app.clamp_contacts_tab_sel();
                    app.clamp_contact_sel();
                    app.set_status(format!("{} removed.", label));
                }
                _ => { /* Esc or anything else cancels */ }
            }
        }

        Modal::ShowQr { hex } => {
            // Any key closes QR display.
            let _ = hex;
        }

        Modal::RevealPhrase { phrase } => {
            // Any key closes phrase display.
            let _ = phrase;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Input editing helper (shared by all text fields)
// ---------------------------------------------------------------------------

pub fn edit_input(input: &mut String, key: KeyEvent) {
    match key.code {
        KeyCode::Char(c) => input.push(c),
        KeyCode::Backspace => { input.pop(); }
        KeyCode::Delete => {} // no cursor tracking needed for simple TUI
        _ => {}
    }
}
