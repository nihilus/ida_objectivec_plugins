/*
 *  This is a sample plugin demonstrating receiving output window notification callbacks
 *  and using of new output window functions: get_output_curline, get_output_cursor,
 *  get_output_selected_text, add_output_popup
 *
 */

#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static form_actions_t *fa;

static void form_msg(const char *format, ...)
{
  textctrl_info_t ti;
  fa->get_text_value(1, &ti);
  va_list va;
  va_start(va, format);
  ti.text.cat_vsprnt(format, va);
  va_end(va);
  fa->set_text_value(1, &ti);
}

//---------------------------------------------------------------------------
static bool idaapi user_menu_cb(void *ud)
{
  char *selection = (char *) ud;
  form_msg("User menu item is called for selection: \"%s\"\n", selection);
  return true;
}

//---------------------------------------------------------------------------
void desc_notification(const char *notification_name)
{
  form_msg("Received notification from output window: \"%s\"\n", notification_name);
}

//---------------------------------------------------------------------------
// Callback for view notifications
static int idaapi ui_callback(void * /*ud*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case msg_activated:
      desc_notification("msg_activated");
      break;
    case msg_deactivated:
      desc_notification("msg_deactivated");
      break;
    case msg_keydown:
      {
        desc_notification("msg_keydown");
        int key = va_arg(va, int);
        int state = va_arg(va, int);
        form_msg("Parameters: Key:%d(\'%c\') State:%d\n", key, key, state);
      }
      break;
    case msg_popup:
      {
        // called when IDA is preparing a context menu for a view
        // Here dynamic context-depending user menu items can be added
        // They will be removed automatically when the pop-up menu is destroyed
        char buf[MAXSTR];
        if ( get_output_selected_text(buf, sizeof(buf)) )
          add_output_popup((char *) "Print selection", user_menu_cb, buf);
        desc_notification("msg_popup");
      }
      break;
    case msg_click:
    case msg_dblclick:
      {
        desc_notification(notification_code == msg_click ? "msg_click" : "msg_dblclick");
        int px = va_arg(va, int);
        int py = va_arg(va, int);
        int state = va_arg(va, int);
        char buf[MAXSTR];
        if ( get_output_curline(buf, sizeof(buf), false) )
          form_msg("Clicked string: %s\n", buf);
        int cx,cy;
        get_output_cursor(&cx, &cy);
        msg("Parameters: x:%d, y:%d, state:%d\n", px, py, state);
        msg("Cursor position:(%d, %d)\n", cx, cy);
      }
      break;
    case msg_closed:
      desc_notification("msg_closed");
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}


//--------------------------------------------------------------------------
// this callback is called when something happens in our editor form
static int idaapi editor_modcb(int fid, form_actions_t &f_actions)
{
  if ( fid == CB_INIT ) // Initialization
  {
    /* set callback for output window notifications */
    hook_to_notification_point(HT_OUTPUT, ui_callback, NULL);
    fa = &f_actions;
  }
  else if ( fid == CB_CLOSE )
  {
    unhook_from_notification_point(HT_OUTPUT, ui_callback, NULL);
  }
  return 1;
}

//--------------------------------------------------------------------------
void idaapi run(int)
{
  static const char formdef[] =
    "BUTTON NO NONE\n"        // we do not want the standard buttons on the form
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Editor form\n"           // the form title. it is also used to refer to the form later
    "\n"
    "%/"                      // placeholder for the 'editor_modcb' callback
    "<Text:t1:30:40:::>\n"    // text edit control
    "\n";

  // structure for text edit control
  textctrl_info_t ti;
  ti.cb = sizeof(textctrl_info_t);
  ti.text = "";

  OpenForm_c(formdef,
             FORM_QWIDGET,
             editor_modcb,
             &ti);
}

static const char wanted_name[] = "HT_OUTPUT notifications handling example";
static const char wanted_hotkey[] = "Ctrl-Alt-F11";
//--------------------------------------------------------------------------
static const char comment[] = "HT_OUTPUT notifications handling";
static const char help[] =
        "This pluging demonstrates handling of output window\n"
        "notifications: Activation/Desactivation, adding\n"
        "popup menus, keyboard and mouse events, changing of current\n"
        "cursor position and closing of view\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  NULL,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
