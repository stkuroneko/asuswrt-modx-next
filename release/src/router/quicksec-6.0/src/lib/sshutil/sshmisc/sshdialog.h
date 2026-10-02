/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header file for ssh_dialog_* functions. You can display generic
   password and generic message boxes with these functions.

   In Win32 sshdialogs.dll must be used. It can be found in
   src/win32/sshdialogs directory.
*/

#ifndef SSH_DIALOG_H
#define SSH_DIALOG_H


#ifdef WIN32
#ifdef EXTERN
#    undef EXTERN
#endif /* EXTERN */
#ifdef __cplusplus
#    define EXTERN extern "C"
#else /* __cplusplus */
#    define EXTERN /**/
#endif /* __cplusplus */
#ifdef _WINDLL
#    define DLL /**/
#ifdef DLLEXPORT
#      undef DLLEXPORT
#endif /* DLLEXPORT */
#    define DLLEXPORT __declspec(dllexport)
#else /* _WINDLL */
#    define DLLEXPORT
#endif /* _WINDLL */
#else /* WIN32 */
#  define DLLEXPORT /**/
#  define EXTERN /**/
#endif /* WIN32 */

/* Styles of buttons we might have in our dialog. */

  /* OK Button */
#define  SSH_DIALOG_BTN_OK 0x01
  /* Cancel Button */
#define  SSH_DIALOG_BTN_CANCEL 0x02
  /* Yes Button */
#define  SSH_DIALOG_BTN_YES 0x04
  /* No Button */
#define  SSH_DIALOG_BTN_NO 0x08

typedef SshUInt32 SshDialogButtonStyles;


/* Callback function that is called when a modeless dialog terminates.
   "input return" will have the data user entered in an input dialog box.
   (In a message box it will be NULL.) Data will be valid only until
   the callback returns, so most applications probably have to mem copy the
   input return. This is because the input return is allocated by the DLL.
   "input_len_return" is the length of the data user has typed.
   "button_pressed" is one of the SshDialogButtonStyles. */
typedef void (*SshDialogCB)(const char *input_return,
                            size_t input_len_return,
                            SshDialogButtonStyles button_pressed,
                            void *context);


/* Callback used to validate users keystrokes.
   A pointer to a function of this type may be passed to the input dialog
   to validate the keystrokes user have entered. Only actual characters
   are to be passed (e.g. no edit control characters). If this callback
   returns FALSE the character is not accepted. */
typedef Boolean (*SshDialogAcceptCharCB)(SshUInt32 ch, void *context);


/* Creates a password dialog with a title and a text. Users key strokes are
   not displayed as a plain text.

   "title"            A title for the dialog
   "text"             A text that is displayed above the input field
   "max_input_len"    The maximum length of characters user can type
                      This is forced by the edit control.
   "accept_char"      Callback used to validate user's keystrokes. If NULL
                      all keystrokes are passed.
   "close_dialog"     The Boolean pointed by this argument is polled with
                      regular intervals inside dialog code to see if the
                      dialog is no more needed. Setting the Boolean to TRUE
                      will cancel the dialog and the close callback will be
                      called with  SSH_DIALOG_BTN_CANCEL. No polling is done
                      if this paramter is NULL.
   "timeout_s"        The time in seconds the dialog is displayed.
   "callback_in"      The function that is called when the dialog terminates.
   "context_in"       The context that is given as the last argumet to the
                      callback_in function.
    Returns TRUE if dialog creation was succesfull. */



EXTERN Boolean DLLEXPORT ssh_dialog_ask_pw(const char *title,
                                    const char *text,
                                    size_t max_input_len,
                                    SshDialogAcceptCharCB accept_char,
                                    Boolean *close_dialog,
                                    SshUInt32 timeout_s,
                                    SshDialogCB callback_in,
                                    void *context_in);


/* Same as above, but the text user enters is displayed as plain. */
EXTERN Boolean DLLEXPORT ssh_dialog_ask(const char *title,
                                 const char *text,
                                 size_t max_input_len,
                                 SshDialogAcceptCharCB accept_char,
                                 Boolean *close_dialog,
                                 SshUInt32 timeout_s,
                                 SshDialogCB callback_in,
                                 void *context_in);


/* Displays a generic message box. Title/text/close_dialog and timeouts
   are as above. This dialog doesn't have any input fields.
   "buttons" specify which buttons are displayed in the dialog. */
EXTERN Boolean DLLEXPORT ssh_dialog_box(const char *title,
                                 const char *text,
                                 SshDialogButtonStyles buttons,
                                 Boolean *close_dialog,
                                 SshUInt32 timeout_s,
                                 SshDialogCB callback_in,
                                 void *context_in);

#endif /* SSH_DIALOG_H */
