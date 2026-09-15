--- a/fs/exec.c
+++ b/fs/exec.c
@@ -1,5 +1,9 @@
 #include <linux/vmalloc.h>
+#ifdef CONFIG_KSU_SUSFS
+#include <linux/susfs_def.h>
+#endif
 
@@ -1,5 +1,15 @@
+#ifdef CONFIG_KSU_SUSFS
+extern struct static_key_true ksu_su_compat_enabled;
+extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;
+extern bool __ksu_is_allow_uid_for_current(uid_t uid);
+extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
+			void *envp, int *flags);
+extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,
+				void *envp, int *flags);
+extern int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,
+			void *envp, int *flags, int *retval);
+#endif
 static int do_execveat_common(int fd, struct filename *filename,
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU_SUSFS
+	bool is_su_session = false;
+#endif // #ifdef CONFIG_KSU_SUSFS
 	if (IS_ERR(filename))
 
@@ -1,5 +1,16 @@
+#ifdef CONFIG_KSU_SUSFS
+	if (likely(susfs_is_current_proc_no_su()))
+		goto orig_flow;
+	if (static_branch_likely(&ksu_su_compat_enabled)) {
+		if (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted))
+		is_su_session = !ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
+	else
+		is_su_session = !ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);
+	}
+orig_flow:
+#endif
 	return PTR_ERR(filename);
 
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU_SUSFS
+	if (unlikely(is_su_session))
+		(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);
+#endif // #ifdef CONFIG_KSU_SUSFS
 out_free:
--- a/fs/open.c
+++ b/fs/open.c
@@ -1,5 +1,8 @@
 #include <linux/compat.h>
+#ifdef CONFIG_KSU_SUSFS
+#include <linux/susfs_def.h>
+#endif
 
@@ -1,5 +1,12 @@
+#ifdef CONFIG_KSU_SUSFS
+extern struct static_key_true ksu_su_compat_enabled;
+extern bool __ksu_is_allow_uid_for_current(uid_t uid);
+extern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,
+             int *flags);
+extern int filename_lookup(int dfd, struct filename *name, unsigned flags,
+				struct path *path, struct path *root);
+#endif
 SYSCALL_DEFINE3(faccessat
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU_SUSFS
+	struct filename *fname = NULL;
+#endif
 	if (mode & ~S_IRWXO)
 
@@ -1,5 +1,16 @@
+#ifdef CONFIG_KSU_SUSFS
+	fname = getname_flags(filename, lookup_flags, NULL);
+
+	if (likely(susfs_is_current_proc_no_su()))
+		goto orig_flow;
+
+	if (static_branch_likely(&ksu_su_compat_enabled)) {
+		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))
+			ksu_handle_faccessat(&dfd, &fname, &mode, NULL);
+	}
+
+orig_flow:
+	res = filename_lookup(dfd, fname, lookup_flags, &path, NULL);
+	// no putname(fname) here as filename_lookup() has it done for us already;
+#else
 	res = user_path_at(dfd, filename, lookup_flags, &path);
+#endif
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU
+extern struct static_key_true ksu_is_init_rc_hook_enabled;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd);
+#endif
 SYSCALL_DEFINE3(read,
 
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU
+	if (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))
+		ksu_handle_sys_read(fd);
+#endif
 	return ksys_read(fd, buf, count);
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -1,5 +1,14 @@
 #include <asm/unistd.h>
+#include "internal.h"
+#ifdef CONFIG_KSU_SUSFS
+#include <linux/susfs_def.h>
+#include "mount.h"
+#endif
+#ifdef CONFIG_KSU_SUSFS
+extern struct static_key_true ksu_is_init_rc_hook_enabled;
+extern void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr);
+extern struct static_key_true ksu_su_compat_enabled;
+extern bool __ksu_is_allow_uid_for_current(uid_t uid);
+extern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);
+#endif // #ifdef CONFIG_KSU_SUSFS
 
@@ -1,5 +1,10 @@
+#ifdef CONFIG_KSU_SUSFS
+	struct filename *fname = NULL;
+extern int filename_lookup(int dfd, struct filename *name, unsigned flags,
+				struct path *path, struct path *root);
+#endif
 	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
 
@@ -1,5 +1,16 @@
+#ifdef CONFIG_KSU_SUSFS
+	fname = getname_flags(filename, lookup_flags, NULL);
+
+	if (likely(susfs_is_current_proc_no_su()))
+		goto orig_flow;
+
+	if (static_branch_likely(&ksu_su_compat_enabled)) {
+		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))
+			ksu_handle_stat(&dfd, &fname, &flags);
+	}
+
+orig_flow:
+	error = filename_lookup(dfd, fname, lookup_flags, &path, NULL);
+	// no putname(fname) here as filename_lookup() has it done for us already;
+#else
 	error = user_path_at(dfd, filename, lookup_flags, &path);
+#endif
 
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU_SUSFS
+		if (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))
+			ksu_handle_vfs_fstat(fd, &stat->size);
+#endif // #ifdef CONFIG_KSU_SUSFS
 	fdput(f);
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1,5 +1,5 @@
-static int filename_lookup(int dfd, struct filename *name, unsigned flags,
+int filename_lookup(int dfd, struct filename *name, unsigned flags,
 
@@ -1,5 +1,11 @@
 	if (unlikely(err)) {
+#ifdef CONFIG_KSU
+		if (unlikely(strstr(current->comm, "throne_tracker"))) {
+			err = -ENOENT;
+			goto out_err;
+		}
+#endif
--- a/drivers/input/input.c
+++ b/drivers/input/input.c
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU
+extern struct static_key_true ksu_is_input_hook_enabled;
+extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
+#endif
 static void input_handle_event(struct input_dev *dev,
 
@@ -1,5 +1,9 @@
 	input_get_disposition(dev, type, code, &value);
+#ifdef CONFIG_KSU_SUSFS
+	if (static_branch_unlikely(&ksu_is_input_hook_enabled))
+		ksu_handle_input_handle_event(&type, &code, &value);
+#endif
--- a/security/security.c
+++ b/security/security.c
@@ -1,5 +1,10 @@
+#ifdef CONFIG_KSU
+extern int ksu_bprm_check(struct linux_binprm *bprm);
+extern int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry);
+extern int ksu_handle_setuid(struct cred *new, const struct cred *old);
+#endif
 int security_binder_set_context_mgr(struct task_struct
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU
+	ksu_bprm_check(bprm);
+#endif
 	ret = security_ops->bprm_check_security(bprm);
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU
+	ksu_handle_rename(old_dentry, new_dentry);
+#endif
 	if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU
+	ksu_handle_setuid(new, old);
+#endif
 	return security_ops->task_fix_setuid(new, old, flags);
--- a/security/selinux/hooks.c
+++ b/security/selinux/hooks.c
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU
+    static u32 ksu_sid;
+    char *secdata;
+#endif
 	int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);
 
@@ -1,5 +1,9 @@
+#ifdef CONFIG_KSU
+    int error;
+    u32 seclen;
+#endif
 	if (!nnp && !nosuid)
 
@@ -1,5 +1,17 @@
 	return 0; /* No change in credentials */
+
+#ifdef CONFIG_KSU
+    if (!ksu_sid)
+        security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);
+
+    error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);
+    if (!error) {
+        rc = strcmp("u:r:init:s0", secdata);
+        security_release_secctx(secdata, seclen);
+        if (rc == 0 && new_tsec->sid == ksu_sid)
+            return 0;
+    }
+#endif
 
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU
+extern int ksu_hide_setprocattr(const char *name, void *value, size_t size);
+#endif
 static int selinux_setprocattr(struct task_struct *p,
 
@@ -1,5 +1,8 @@
 	char *str = value;
+#ifdef CONFIG_KSU
+	ksu_hide_setprocattr(name, value, size);
+#endif
--- a/security/selinux/ss/services.c
+++ b/security/selinux/ss/services.c
@@ -1,2 +1,2 @@
-static DEFINE_RWLOCK(policy_rwlock);
+DEFINE_RWLOCK(policy_rwlock);
--- a/kernel/reboot.c
+++ b/kernel/reboot.c
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU_SUSFS
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
+#endif
 SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
 
@@ -1,5 +1,10 @@
 	int ret = 0;
+#ifdef CONFIG_KSU_SUSFS
+    if (system_state == SYSTEM_RUNNING) {
+        ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+    }
+#endif
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -1,5 +1,8 @@
+#ifdef CONFIG_KSU
+extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
+#endif
 SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 
@@ -1,5 +1,10 @@
+#ifdef CONFIG_KSU_SUSFS
+	if (ksu_handle_setresuid(ruid, euid, suid)) {
+		pr_info("Something wrong with ksu_handle_setresuid()\\n");
+	}
+#endif
 	return __sys_setresuid(ruid, euid, suid);
