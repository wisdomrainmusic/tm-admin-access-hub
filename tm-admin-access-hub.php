<?php
/**
 * Plugin Name: TM Admin Access Hub
 * Description: Role-based admin menu control with tabs + capability bridges (Woo Analytics, Site Kit, Fluent). Safe-by-default (hide only).
 * Version: 2.0.3
 * Author: Terzi Mankeni
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('TM_Admin_Access_Hub_V2', false)) {

class TM_Admin_Access_Hub_V2 {

    const OPT_KEY = 'tm_aah_v2_settings';
    const SLUG    = 'tm-admin-access-hub';

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'register_admin_page'), 20);
        add_action('admin_init', array(__CLASS__, 'handle_post'));

        // Apply menu visibility rules late
        add_action('admin_menu', array(__CLASS__, 'apply_menu_visibility'), 999);

        // Capability bridge for allowed plugin areas (Shop Manager, etc.)
        add_filter('user_has_cap', array(__CLASS__, 'capability_bridge'), 20, 4);
    }

    /* =========================
     * Core helpers
     * ========================= */

    private static function settings_get() {
        $s = get_option(self::OPT_KEY, array());
        if (!is_array($s)) $s = array();

        // defaults
        if (!isset($s['mode'])) $s['mode'] = 'hide_only'; // hide_only | hide_and_block (block later if needed)
        if (!isset($s['roles'])) $s['roles'] = array();   // per-role allowlists
        if (!isset($s['bridge'])) $s['bridge'] = array(
            'enabled' => 1,
            'woocommerce' => 1,
            'sitekit' => 1,
            'fluent' => 1,
        );

        return $s;
    }

    private static function settings_save($s) {
        if (!is_array($s)) $s = array();
        update_option(self::OPT_KEY, $s, false);
    }

    private static function current_role() {
        $u = wp_get_current_user();
        if (empty($u) || empty($u->roles)) return '';
        return (string) $u->roles[0];
    }

    private static function is_protected_admin() {
        // Admin (manage_options) asla etkilenmesin
        return current_user_can('manage_options');
    }

    private static function norm($slug) {
        $slug = (string) $slug;
        $slug = html_entity_decode($slug, ENT_QUOTES, 'UTF-8');
        return trim($slug);
    }

    /**
     * Extract a comparable "base" from a menu slug.
     * Examples:
     *  - admin.php?page=wc-admin&path=/analytics/overview  => wc-admin
     *  - wc-admin&path=/analytics/overview                 => wc-admin
     *  - edit.php?post_type=product                        => edit.php
     */
    private static function base_slug($slug) {
        $slug = self::norm($slug);
        if ($slug === '') return '';

        if (strpos($slug, 'admin.php?page=') === 0) {
            $slug = substr($slug, strlen('admin.php?page='));
        }

        $cut = strcspn($slug, "&?");
        $base = substr($slug, 0, $cut);
        return self::norm($base);
    }

    /**
     * Loose allowlist check:
     * - exact match
     * - base slug match (wc-admin equals wc-admin&path=...)
     * - allowlist item is prefix of slug (for query args)
     */
    private static function is_allowed_slug($slug, $allowlist) {
        $slug = self::norm($slug);
        if ($slug === '') return false;

        $base = self::base_slug($slug);

        foreach ((array)$allowlist as $it) {
            $it = self::norm($it);
            if ($it === '') continue;

            if ($it === $slug) return true;
            if ($base !== '' && $it === $base) return true;
            if (strpos($slug, $it) === 0) return true;

            $it_base = self::base_slug($it);
            if ($it_base !== '' && $it_base === $base) return true;
        }

        return false;
    }

    private static function is_cross_parent_allowed($item_slug, $allowed_flat) {
        $item_slug = self::norm($item_slug);
        if ($item_slug === '') return false;

        // Only apply cross-parent fallback for wc-admin "home" item (no &path=...).
        // If it's a specific wc-admin path (extensions/customers/analytics...), it must be explicitly allowed.
        $is_wc_admin_home =
            ($item_slug === 'wc-admin') ||
            (strpos($item_slug, 'admin.php?page=wc-admin') === 0 && strpos($item_slug, '&') === false);

        if ($is_wc_admin_home) {
            // Show wc-admin home if ANY wc-admin-related item is allowed somewhere.
            foreach ((array)$allowed_flat as $it) {
                $it = self::norm($it);
                if ($it === '') continue;
                if (self::base_slug($it) === 'wc-admin') return true;
                if (strpos($it, 'wc-admin') === 0) return true;
            }
        }

        return false;
    }

    private static function flatten_allow($role_rules) {
        $out = array();

        $top = isset($role_rules['allow_top']) && is_array($role_rules['allow_top']) ? $role_rules['allow_top'] : array();
        foreach ($top as $v) $out[] = (string) $v;

        $sub = isset($role_rules['allow_sub']) && is_array($role_rules['allow_sub']) ? $role_rules['allow_sub'] : array();
        foreach ($sub as $parent => $subs) {
            if (!is_array($subs)) continue;
            foreach ($subs as $v) $out[] = (string) $v;
        }

        $out = array_map(array(__CLASS__, 'norm'), $out);
        $out = array_values(array_unique(array_filter($out)));
        return $out;
    }

    /**
     * When settings are imported manually, it's possible to have submenu allowlists
     * without the parent in allow_top. To prevent "I checked it but it doesn't show"
     * cases, we auto-include any parent that has at least one allowed submenu.
     */
    private static function ensure_parents_allowed(&$allow_top, $allow_sub) {
        if (!is_array($allow_top)) $allow_top = array();
        if (!is_array($allow_sub)) $allow_sub = array();

        foreach ($allow_sub as $parent => $subs) {
            $parent = self::norm($parent);
            if ($parent === '') continue;
            if (!is_array($subs) || empty($subs)) continue;

            if (!in_array($parent, $allow_top, true)) {
                $allow_top[] = $parent;
            }
        }

        $allow_top = array_values(array_unique(array_filter(array_map(array(__CLASS__, 'norm'), $allow_top))));
    }

    /* =========================
     * Admin page / Tabs
     * ========================= */

    public static function register_admin_page() {
        if (!current_user_can('manage_options')) return;

        add_menu_page(
            'TM Admin Access Hub',
            'TM Access Hub',
            'manage_options',
            self::SLUG,
            array(__CLASS__, 'render_page'),
            'dashicons-shield',
            2
        );
    }

    public static function render_page() {
        if (!current_user_can('manage_options')) return;

        $s = self::settings_get();
        $tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'roles';
        $saved = isset($_GET['saved']) && $_GET['saved'] === '1';

        $roles = wp_roles()->roles;
        if (isset($roles['administrator'])) unset($roles['administrator']);

        $active_role = isset($_GET['role']) ? sanitize_text_field($_GET['role']) : '';
        if ($active_role === '' && isset($roles['shop_manager'])) $active_role = 'shop_manager';
        if ($active_role === '' && !empty($roles)) {
            foreach ($roles as $k => $v) { $active_role = $k; break; }
        }
        if (!isset($roles[$active_role])) {
            // fallback
            foreach ($roles as $k => $v) { $active_role = $k; break; }
        }

        $role_rules = isset($s['roles'][$active_role]) && is_array($s['roles'][$active_role]) ? $s['roles'][$active_role] : array(
            'allow_top' => array(),
            'allow_sub' => array(),
        );

        $menu_map = self::get_menu_map_live();

        ?>
        <div class="wrap">
            <h1>TM Admin Access Hub</h1>

            <?php if ($saved): ?>
                <div class="notice notice-success is-dismissible"><p>Kaydedildi.</p></div>
            <?php endif; ?>

            <h2 class="nav-tab-wrapper">
                <a class="nav-tab <?php echo ($tab==='roles'?'nav-tab-active':''); ?>" href="<?php echo esc_url(self::tab_url('roles', $active_role)); ?>">Roles</a>
                <a class="nav-tab <?php echo ($tab==='menus'?'nav-tab-active':''); ?>" href="<?php echo esc_url(self::tab_url('menus', $active_role)); ?>">Menus</a>
                <a class="nav-tab <?php echo ($tab==='bridges'?'nav-tab-active':''); ?>" href="<?php echo esc_url(self::tab_url('bridges', $active_role)); ?>">Bridges</a>
                <a class="nav-tab <?php echo ($tab==='diagnostics'?'nav-tab-active':''); ?>" href="<?php echo esc_url(self::tab_url('diagnostics', $active_role)); ?>">Diagnostics</a>
                <a class="nav-tab <?php echo ($tab==='export'?'nav-tab-active':''); ?>" href="<?php echo esc_url(self::tab_url('export', $active_role)); ?>">Export</a>
            </h2>

            <?php if ($tab === 'roles'): ?>
                <?php self::render_tab_roles($s, $roles, $active_role); ?>
            <?php elseif ($tab === 'menus'): ?>
                <?php self::render_tab_menus($s, $roles, $active_role, $role_rules, $menu_map); ?>
            <?php elseif ($tab === 'bridges'): ?>
                <?php self::render_tab_bridges($s); ?>
            <?php elseif ($tab === 'diagnostics'): ?>
                <?php self::render_tab_diagnostics($s, $active_role, $role_rules); ?>
            <?php else: ?>
                <?php self::render_tab_export($s); ?>
            <?php endif; ?>

        </div>
        <?php
    }

    private static function tab_url($tab, $role) {
        return add_query_arg(array(
            'page' => self::SLUG,
            'tab'  => $tab,
            'role' => $role,
        ), admin_url('admin.php'));
    }

    private static function render_tab_roles($s, $roles, $active_role) {
        $mode = isset($s['mode']) ? $s['mode'] : 'hide_only';
        $nonce = wp_create_nonce('tm_aah_save_roles');
        ?>
        <form method="post">
            <input type="hidden" name="tm_aah_action" value="save_roles" />
            <input type="hidden" name="tm_aah_nonce" value="<?php echo esc_attr($nonce); ?>" />

            <p>
                <strong>Active role:</strong>
                <select name="active_role" onchange="window.location='<?php echo esc_js(self::tab_url('roles','')); ?>'.replace('role=','role='+this.value)">
                    <?php foreach ($roles as $rk => $rd): ?>
                        <option value="<?php echo esc_attr($rk); ?>" <?php selected($active_role, $rk); ?>>
                            <?php echo esc_html($rd['name']); ?> (<?php echo esc_html($rk); ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </p>

            <p>
                <strong>Mode</strong><br/>
                <label><input type="radio" name="mode" value="hide_only" <?php checked($mode, 'hide_only'); ?> /> Hide only (safe)</label><br/>
                <label><input type="radio" name="mode" value="hide_and_block" <?php checked($mode, 'hide_and_block'); ?> /> Hide + block direct access (later)</label>
            </p>

            <p><button class="button button-primary" type="submit">Save</button></p>

            <p style="color:#666;">
                Not: Admin (manage_options) hiçbir zaman etkilenmez.
            </p>
        </form>
        <?php
    }

    private static function render_tab_menus($s, $roles, $active_role, $role_rules, $menu_map) {
        $nonce = wp_create_nonce('tm_aah_save_menus');
        ?>
        <form method="get" action="">
            <input type="hidden" name="page" value="<?php echo esc_attr(self::SLUG); ?>" />
            <input type="hidden" name="tab" value="menus" />
            <label><strong>Role:</strong></label>
            <select name="role" onchange="this.form.submit()">
                <?php foreach ($roles as $rk => $rd): ?>
                    <option value="<?php echo esc_attr($rk); ?>" <?php selected($active_role, $rk); ?>>
                        <?php echo esc_html($rd['name']); ?> (<?php echo esc_html($rk); ?>)
                    </option>
                <?php endforeach; ?>
            </select>
        </form>

        <hr/>

        <form method="post">
            <input type="hidden" name="tm_aah_action" value="save_menus" />
            <input type="hidden" name="tm_aah_nonce" value="<?php echo esc_attr($nonce); ?>" />
            <input type="hidden" name="role" value="<?php echo esc_attr($active_role); ?>" />

            <p style="color:#444;">
                İşaretlediğin menüler Shop Manager için görünür olur. <strong>Görünen menüler için erişim sınırsızdır</strong> (bridge ile).
            </p>

            <h2>Top menus</h2>
            <div style="display:grid;grid-template-columns:repeat(2,minmax(320px,1fr));gap:10px;max-width:980px;">
                <?php foreach ($menu_map['top'] as $slug => $title): ?>
                    <?php
                        $checked = in_array($slug, (array)($role_rules['allow_top'] ?? array()), true);
                    ?>
                    <label style="padding:8px 10px;border:1px solid #dcdcde;border-radius:6px;background:#fff;">
                        <input type="checkbox" name="allow_top[]" value="<?php echo esc_attr($slug); ?>" <?php checked($checked); ?> />
                        <?php echo esc_html($title); ?>
                        <div style="color:#777;font-size:12px;margin-top:4px;"><?php echo esc_html($slug); ?></div>
                    </label>
                <?php endforeach; ?>
            </div>

            <h2 style="margin-top:22px;">Sub menus</h2>
            <?php foreach ($menu_map['sub'] as $parent => $subs): ?>
                <h3 style="margin-top:18px;"><?php echo esc_html($parent); ?></h3>
                <div style="display:grid;grid-template-columns:repeat(2,minmax(320px,1fr));gap:10px;max-width:980px;">
                    <?php foreach ($subs as $sub_slug => $sub_title): ?>
                        <?php
                            $allowed = isset($role_rules['allow_sub'][$parent]) && is_array($role_rules['allow_sub'][$parent]) ? $role_rules['allow_sub'][$parent] : array();
                            $checked = in_array($sub_slug, $allowed, true);
                        ?>
                        <label style="padding:8px 10px;border:1px solid #dcdcde;border-radius:6px;background:#fff;">
                            <input type="checkbox" name="allow_sub[<?php echo esc_attr($parent); ?>][]" value="<?php echo esc_attr($sub_slug); ?>" <?php checked($checked); ?> />
                            <?php echo esc_html($sub_title); ?>
                            <div style="color:#777;font-size:12px;margin-top:4px;"><?php echo esc_html($sub_slug); ?></div>
                        </label>
                    <?php endforeach; ?>
                </div>
            <?php endforeach; ?>

            <p style="margin-top:18px;">
                <button class="button button-primary" type="submit">Save menu rules</button>
            </p>
        </form>
        <?php
    }

    private static function render_tab_bridges($s) {
        $b = isset($s['bridge']) && is_array($s['bridge']) ? $s['bridge'] : array();
        $nonce = wp_create_nonce('tm_aah_save_bridges');
        ?>
        <form method="post">
            <input type="hidden" name="tm_aah_action" value="save_bridges" />
            <input type="hidden" name="tm_aah_nonce" value="<?php echo esc_attr($nonce); ?>" />

            <p><label><input type="checkbox" name="bridge_enabled" value="1" <?php checked(!empty($b['enabled'])); ?> /> Enable capability bridges</label></p>

            <h3>Bridge presets</h3>
            <label><input type="checkbox" name="bridge_woocommerce" value="1" <?php checked(!empty($b['woocommerce'])); ?> /> WooCommerce + Analytics (wc-admin)</label><br/>
            <label><input type="checkbox" name="bridge_sitekit" value="1" <?php checked(!empty($b['sitekit'])); ?> /> Google Site Kit</label><br/>
            <label><input type="checkbox" name="bridge_fluent" value="1" <?php checked(!empty($b['fluent'])); ?> /> Fluent (Forms/SMTP/CRM)</label>

            <p style="margin-top:14px;">
                <button class="button button-primary" type="submit">Save bridges</button>
            </p>

            <p style="color:#666;">
                Bridge mantığı: Rol allowlist’inde ilgili eklenti/menü slug’ı varsa gerekli capability’ler otomatik verilir.
            </p>
        </form>
        <?php
    }

    private static function render_tab_diagnostics($s, $active_role, $role_rules) {
        $u = wp_get_current_user();
        $role = self::current_role();
        $flat = self::flatten_allow($role_rules);

        $pagenow = isset($GLOBALS['pagenow']) ? (string)$GLOBALS['pagenow'] : '';
        $page = isset($_GET['page']) ? sanitize_text_field($_GET['page']) : '';
        $path = isset($_GET['path']) ? sanitize_text_field($_GET['path']) : '';
        if ($path !== '') $path = rawurldecode($path);

        ?>
        <div style="background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:14px;max-width:980px;">
            <h2>Diagnostics</h2>
            <p><strong>Logged-in user:</strong> <?php echo esc_html($u->user_login); ?></p>
            <p><strong>Current role:</strong> <?php echo esc_html($role); ?></p>
            <p><strong>Protected admin bypass:</strong> <?php echo self::is_protected_admin() ? 'YES' : 'NO'; ?></p>
            <hr/>
            <p><strong>Request:</strong> pagenow=<?php echo esc_html($pagenow); ?> | page=<?php echo esc_html($page); ?> | path=<?php echo esc_html($path); ?></p>
            <p><strong>Active config role:</strong> <?php echo esc_html($active_role); ?></p>
            <p><strong>Allowed items count:</strong> <?php echo (int)count($flat); ?></p>

            <details style="margin-top:10px;">
                <summary>Show allowed slugs</summary>
                <div style="margin-top:8px;font-family:monospace;font-size:12px;white-space:pre-wrap;">
                    <?php echo esc_html(implode("\n", $flat)); ?>
                </div>
            </details>

            <p style="color:#666;margin-top:10px;">
                Eğer “Site Kit görünmüyor” ise bu sayfada role allowlist’inde googlesitekit slug’ı var mı kontrol et.
                Eğer “Analiz erişemiyor” ise allowlist’te wc-admin var mı kontrol et.
            </p>
        </div>
        <?php
    }

    private static function render_tab_export($s) {
        $nonce = wp_create_nonce('tm_aah_export');
        $json = wp_json_encode($s);
        ?>
        <div style="max-width:980px;">
            <h2>Export / Import</h2>

            <h3>Export</h3>
            <textarea style="width:100%;min-height:160px;font-family:monospace;"><?php echo esc_textarea($json); ?></textarea>

            <h3 style="margin-top:18px;">Import</h3>
            <form method="post">
                <input type="hidden" name="tm_aah_action" value="import" />
                <input type="hidden" name="tm_aah_nonce" value="<?php echo esc_attr($nonce); ?>" />
                <textarea name="import_json" style="width:100%;min-height:160px;font-family:monospace;"></textarea>
                <p><button class="button button-primary" type="submit">Import settings</button></p>
            </form>
        </div>
        <?php
    }

    public static function handle_post() {
        if (!current_user_can('manage_options')) return;
        if (!isset($_POST['tm_aah_action'])) return;

        $action = sanitize_text_field($_POST['tm_aah_action']);
        $s = self::settings_get();

        if ($action === 'save_roles') {
            $nonce = isset($_POST['tm_aah_nonce']) ? sanitize_text_field($_POST['tm_aah_nonce']) : '';
            if (!wp_verify_nonce($nonce, 'tm_aah_save_roles')) wp_die('Security check failed');

            $mode = isset($_POST['mode']) ? sanitize_text_field($_POST['mode']) : 'hide_only';
            if ($mode !== 'hide_only' && $mode !== 'hide_and_block') $mode = 'hide_only';
            $s['mode'] = $mode;

            self::settings_save($s);
            wp_safe_redirect(add_query_arg(array('page'=>self::SLUG,'tab'=>'roles','saved'=>'1'), admin_url('admin.php')));
            exit;
        }

        if ($action === 'save_menus') {
            $nonce = isset($_POST['tm_aah_nonce']) ? sanitize_text_field($_POST['tm_aah_nonce']) : '';
            if (!wp_verify_nonce($nonce, 'tm_aah_save_menus')) wp_die('Security check failed');

            $role = isset($_POST['role']) ? sanitize_text_field($_POST['role']) : '';
            if ($role === '' || $role === 'administrator') wp_die('Invalid role');

            $allow_top = array();
            if (isset($_POST['allow_top']) && is_array($_POST['allow_top'])) {
                $allow_top = array_map(array(__CLASS__, 'norm'), (array)wp_unslash($_POST['allow_top']));
                $allow_top = array_values(array_unique(array_filter($allow_top)));
            }

            $allow_sub = array();
            if (isset($_POST['allow_sub']) && is_array($_POST['allow_sub'])) {
                $raw_parent = (array) wp_unslash($_POST['allow_sub']);
                foreach ($raw_parent as $parent => $subs) {
                    $parent = self::norm($parent);
                    if (!is_array($subs)) continue;
                    $subs = array_map(array(__CLASS__, 'norm'), (array)$subs);
                    $subs = array_values(array_unique(array_filter($subs)));
                    $allow_sub[$parent] = $subs;
                }
            }

            if (!isset($s['roles']) || !is_array($s['roles'])) $s['roles'] = array();
            $s['roles'][$role] = array('allow_top'=>$allow_top, 'allow_sub'=>$allow_sub);

            self::settings_save($s);
            wp_safe_redirect(add_query_arg(array('page'=>self::SLUG,'tab'=>'menus','role'=>$role,'saved'=>'1'), admin_url('admin.php')));
            exit;
        }

        if ($action === 'save_bridges') {
            $nonce = isset($_POST['tm_aah_nonce']) ? sanitize_text_field($_POST['tm_aah_nonce']) : '';
            if (!wp_verify_nonce($nonce, 'tm_aah_save_bridges')) wp_die('Security check failed');

            $s['bridge'] = array(
                'enabled' => !empty($_POST['bridge_enabled']) ? 1 : 0,
                'woocommerce' => !empty($_POST['bridge_woocommerce']) ? 1 : 0,
                'sitekit' => !empty($_POST['bridge_sitekit']) ? 1 : 0,
                'fluent' => !empty($_POST['bridge_fluent']) ? 1 : 0,
            );

            self::settings_save($s);
            wp_safe_redirect(add_query_arg(array('page'=>self::SLUG,'tab'=>'bridges','saved'=>'1'), admin_url('admin.php')));
            exit;
        }

        if ($action === 'import') {
            $nonce = isset($_POST['tm_aah_nonce']) ? sanitize_text_field($_POST['tm_aah_nonce']) : '';
            if (!wp_verify_nonce($nonce, 'tm_aah_export')) wp_die('Security check failed');

            $json = isset($_POST['import_json']) ? wp_unslash($_POST['import_json']) : '';
            $data = json_decode($json, true);
            if (!is_array($data)) wp_die('Invalid JSON');

            self::settings_save($data);
            wp_safe_redirect(add_query_arg(array('page'=>self::SLUG,'tab'=>'export','saved'=>'1'), admin_url('admin.php')));
            exit;
        }
    }

    /* =========================
     * Live menu discovery
     * ========================= */

    private static function get_menu_map_live() {
        global $menu, $submenu;

        $top = array();
        $sub = array();

        if (is_array($menu)) {
            foreach ($menu as $m) {
                if (!is_array($m) || !isset($m[2])) continue;
                $slug = self::norm($m[2]);
                if ($slug === '' || strpos($slug, 'separator') === 0) continue;

                $title = isset($m[0]) ? wp_strip_all_tags($m[0]) : $slug;
                $top[$slug] = $title;
            }
        }

        if (is_array($submenu)) {
            foreach ($submenu as $parent => $items) {
                $parent = self::norm($parent);
                if (!is_array($items)) continue;
                foreach ($items as $it) {
                    if (!is_array($it) || !isset($it[2])) continue;
                    $sub_slug = self::norm($it[2]);
                    $sub_title = isset($it[0]) ? wp_strip_all_tags($it[0]) : $sub_slug;

                    if (!isset($sub[$parent])) $sub[$parent] = array();
                    $sub[$parent][$sub_slug] = $sub_title;
                }
            }
        }

        ksort($top);
        ksort($sub);

        return array('top'=>$top, 'sub'=>$sub);
    }

    /* =========================
     * Menu visibility enforcement
     * ========================= */

    public static function apply_menu_visibility() {
        if (self::is_protected_admin()) return;

        $role = self::current_role();
        if ($role === '') return;

        $s = self::settings_get();
        $role_rules = isset($s['roles'][$role]) ? $s['roles'][$role] : null;
        if (!is_array($role_rules)) return;

        $allow_top = isset($role_rules['allow_top']) && is_array($role_rules['allow_top']) ? $role_rules['allow_top'] : array();
        $allow_sub = isset($role_rules['allow_sub']) && is_array($role_rules['allow_sub']) ? $role_rules['allow_sub'] : array();

        // Normalize: if a parent has allowed submenus, ensure parent is also treated as allowed.
        self::ensure_parents_allowed($allow_top, $allow_sub);

        // Always keep Dashboard
        if (!in_array('index.php', $allow_top, true)) $allow_top[] = 'index.php';

        global $menu, $submenu;

        // Hide top menus not allowed
        if (is_array($menu)) {
            foreach ($menu as $item) {
                if (!is_array($item) || !isset($item[2])) continue;
                $slug = self::norm($item[2]);
                if ($slug === '' || strpos($slug, 'separator') === 0) continue;

                if (!self::is_allowed_slug($slug, $allow_top)) {
                    remove_menu_page($slug);
                }
            }
        }

        // Hide submenus not allowed (under allowed parents only)
        if (is_array($submenu)) {
            foreach ($submenu as $parent_slug => $subs) {
                $parent_slug_norm = self::norm($parent_slug);
                if (!self::is_allowed_slug($parent_slug_norm, $allow_top)) continue;

                $allowed_subs = isset($allow_sub[$parent_slug_norm]) && is_array($allow_sub[$parent_slug_norm]) ? $allow_sub[$parent_slug_norm] : array();

                if (is_array($subs)) {
                    foreach ($subs as $sub) {
                        if (!is_array($sub) || !isset($sub[2])) continue;
                        $sub_slug = self::norm($sub[2]);

                        if (!self::is_allowed_slug($sub_slug, $allowed_subs)) {
                            // Cross-parent fallback: only wc-admin HOME
                            if (!self::is_cross_parent_allowed($sub_slug, self::flatten_allow($role_rules))) {
                                remove_submenu_page($parent_slug_norm, $sub_slug);
                            }
                        }
                    }
                }
            }
        }
    }

    /* =========================
     * Capability bridge (key part)
     * ========================= */

    public static function capability_bridge($allcaps, $caps, $args, $user) {
        if (empty($user) || empty($user->roles)) return $allcaps;
        if (in_array('administrator', (array)$user->roles, true)) return $allcaps;

        $s = self::settings_get();
        $bridge = isset($s['bridge']) ? $s['bridge'] : array();
        if (empty($bridge['enabled'])) return $allcaps;

        $role = (string) $user->roles[0];
        if ($role === '') return $allcaps;

        $role_rules = isset($s['roles'][$role]) ? $s['roles'][$role] : null;
        if (!is_array($role_rules)) return $allcaps;

        $allowed = self::flatten_allow($role_rules);
        $hay = strtolower(implode(' | ', $allowed));

        // If you allowed Woo Analytics / wc-admin, grant analytics caps
        if (!empty($bridge['woocommerce'])) {
            if (strpos($hay, 'wc-admin') !== false || strpos($hay, 'woocommerce') !== false) {
                $allcaps['manage_woocommerce'] = true;
                $allcaps['view_woocommerce_reports'] = true;
                $allcaps['view_woocommerce_analytics'] = true;

                // Woo Admin / Analytics variations (different WC versions/plugins may check these)
                $allcaps['view_woocommerce_admin_dashboard'] = true;
                $allcaps['view_woocommerce_admin_analytics'] = true;
                $allcaps['view_woocommerce_admin_reports'] = true;
                $allcaps['view_woocommerce_admin_pages'] = true;
                $allcaps['view_woocommerce_admin_tools'] = true;

                // Common shop-manager needs
                $allcaps['edit_products'] = true;
                $allcaps['read_product'] = true;
                $allcaps['edit_shop_orders'] = true;
                $allcaps['read_shop_order'] = true;
            }
        }

        // If you allowed Site Kit menu, grant site kit caps
        if (!empty($bridge['sitekit'])) {
            if (strpos($hay, 'googlesitekit') !== false || strpos($hay, 'sitekit') !== false || strpos($hay, 'site-kit') !== false) {
                $allcaps['googlesitekit_view_dashboard'] = true;
                $allcaps['googlesitekit_manage_options'] = true;
                $allcaps['googlesitekit_view_splash'] = true;
            }
        }

        // If you allowed Fluent menus, grant fluent caps
        if (!empty($bridge['fluent'])) {
            if (strpos($hay, 'fluent') !== false) {
                $allcaps['fluentform_dashboard_access'] = true;
                $allcaps['fluentform_manage_forms'] = true;
                $allcaps['fluentform_manage_entries'] = true;
                $allcaps['fluentform_view_entries'] = true;

                $allcaps['fluentsmtp_manage_settings'] = true;
                $allcaps['fluentsmtp_view_logs'] = true;

                $allcaps['fluentcrm_access'] = true;
                $allcaps['fluentcrm_read'] = true;
                $allcaps['fluentcrm_manage'] = true;
            }
        }

        return $allcaps;
    }
}

TM_Admin_Access_Hub_V2::init();

} // class exists guard
