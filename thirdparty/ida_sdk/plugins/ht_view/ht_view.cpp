/*
 *  This is a sample plugin demonstrating usage of the view callbacks
 *  and adding custom menu items to popup menus
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <graph.hpp>


//---------------------------------------------------------------------------
static bool idaapi user_menu_dynamic_cb(void *)
{
  msg("User dynamic menu item is called\n");
  return true;
}

//---------------------------------------------------------------------------
static bool idaapi user_menu_permanent_cb(void *)
{
  msg("User permanent menu item is called\n");
  return true;
}

//---------------------------------------------------------------------------
void desc_notification(const char *notification_name, TCustomControl *cv)
{
  char buffer[MAXSTR];
  get_viewer_name(cv, buffer, sizeof(buffer));
  msg("Received notification from view %s: \"%s\"\n", buffer, notification_name);
}

//-------------------------------------------------------------------------
void desc_mouse_event(const view_mouse_event_t *event)
{
  int px = event->x;
  int py = event->y;
  int state = event->state;
  qstring over_txt;
  const selection_item_t *item = event->location.item;
  if ( event->rtype != TCCRT_FLAT && item != NULL )
  {
    if ( item->is_node )
      over_txt.sprnt("node %d", item->node);
    else
      over_txt.sprnt("edge %d -> %d", item->elp.e.src, item->elp.e.dst);
  }
  else
  {
    over_txt = "(nothing)";
  }
  msg("Parameters: x:%d, y:%d, state:%d, over:%s\n", px, py, state, over_txt.c_str());
}

//---------------------------------------------------------------------------
// Callback for view notifications
static int idaapi ui_callback(void * /*ud*/, int notification_code, va_list va)
{
  TCustomControl *view = va_arg(va, TCustomControl *);
  switch ( notification_code )
  {
    case view_activated:
      desc_notification("view_activated", view);
      break;
    case view_deactivated:
      desc_notification("view_deactivated", view);
      break;
    case view_keydown:
      {
        desc_notification("view_keydown", view);
        int key = va_arg(va, int);
        int state = va_arg(va, int);
        msg("Parameters: Key:%d(\'%c\') State:%d\n", key, key, state);
      }
      break;
    case view_popup:
      {
        // called when IDA is preparing a context menu for a view
        // Here dynamic context-dependent user menu items can be added
        // They will be removed automatically when the pop-up menu is destroyed
        desc_notification("view_popup", view);
        // clear the current user-defined menu (may clear items added by other plugins, so not recommended)
        // set_custom_viewer_popup_menu(viewer, NULL);

        add_custom_viewer_popup_item(view, "Dynamic menu item", NULL, user_menu_dynamic_cb, NULL);
      }
      break;
    case view_click:
    case view_dblclick:
      {
        desc_notification(notification_code == view_click ? "view_click" : "view_dblclick", view);
        desc_mouse_event(va_arg(va, view_mouse_event_t*));
        int cx,cy;
        get_cursor(&cx, &cy);
        msg("Cursor position:(%d, %d)\n", cx, cy);
      }
      break;
    case view_curpos:
      {
        desc_notification("view_curpos", view);
        if ( is_idaview(view) )
        {
          char buf[MAXSTR];
          ea2str(get_screen_ea(), buf, sizeof(buf));
          msg("New address: %s\n", buf);
        }
      }
      break;
    case view_mouse_over:
      {
        desc_notification("view_mouse_over", view);
        desc_mouse_event(va_arg(va, view_mouse_event_t*));
      }
      break;
    case view_close:
      desc_notification("view_close", view);
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_VIEW, ui_callback, NULL);
}

bool hooked = false;
//--------------------------------------------------------------------------
void idaapi run(int)
{
  /* set callback for view notifications */
  if ( !hooked )
  {
    hook_to_notification_point(HT_VIEW, ui_callback, NULL);
    hooked = true;
    msg("HT_VIEW: installed view notification hook.\n");
  }

  // User popup menu items for the view can be created here
  TCustomControl *viewer = (TCustomControl*)(callui(ui_get_current_viewer).vptr);
  // clear the current user-defined menu
  set_custom_viewer_popup_menu(viewer, NULL);
  add_custom_viewer_popup_item(viewer, "Permanent menu item", NULL, user_menu_permanent_cb, NULL);
}

static const char wanted_name[] = "HT_VIEW notification handling example";
static const char wanted_hotkey[] = "Alt-F12";
//--------------------------------------------------------------------------
static const char comment[] = "HT_VIEW notification Handling";
static const char help[] =
        "This pluging demonstrates handling of custom and IdaView\n"
        "notifications: Activation/Desactivation of views, adding\n"
        "popup menus, keyboard and mouse events, changing of current\n"
        "address and closing of view\n";

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

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
