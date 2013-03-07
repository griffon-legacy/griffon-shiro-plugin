class ShiroGriffonPlugin {
    // the plugin version
    String version = '0.1'
    // the version or versions of Griffon the plugin is designed for
    String griffonVersion = '1.3.0 > *'
    // the other plugins this plugin depends on
    Map dependsOn = [:]
    // resources that are included in plugin packaging
    List pluginIncludes = []
    // the plugin license
    String license = 'Apache Software License 2.0'
    // Toolkit compatibility. No value means compatible with all
    // Valid values are: swing, javafx, swt, pivot, gtk
    List toolkits = []
    // Platform compatibility. No value means compatible with all
    // Valid values are:
    // linux, linux64, windows, windows64, macosx, macosx64, solaris
    List platforms = []
    // URL where documentation can be found
    String documentation = ''
    // URL where source can be found
    String source = 'https://github.com/griffon/griffon-shiro-plugin'

    List authors = [
        [
            name: 'Andres Almiray',
            email: 'aalmiray@yahoo.com'
        ]
    ]
    String title = 'Secure applications using Apache Shiro'
    // accepts Markdown syntax. See http://daringfireball.net/projects/markdown/ for details
    String description = '''
[Apache Shiro][1] is a powerful and easy-to-use Java security framework that
performs authentication, authorization, cryptography, and session management.

This plugin enables access control on controller actions via a set of annotations.
Security checks will be performed before an action is invoked. Annotated actions
will be executed if the user meets the security criteria, otherwise execution is
aborted. The plugin assumes sensible defaults where needed but also lets you
customize behavior.

Usage
-----

Controller actions, whether they are defined as method or closure properties, must
be annotated with any of the following annotations

 * `@griffon.plugins.shiro.annotation.RequiresAuthentication` - Requires the
   current Subject to have been authenticated during their current session for
   the annotated class/instance/method to be accessed or invoked
 * `@griffon.plugins.shiro.annotation.RequiresGuest` - Requires the current
   Subject to be a "guest", that is, they are not authenticated or remembered
   from a previous session for the annotated class/instance/method to be
   accessed or invoked.
 * `@griffon.plugins.shiro.annotation.RequiresPermissions` - Requires the
   current executor's Subject to imply a particular permission in order to
   execute the annotated method. If the executor's associated Subject determines
   that the executor does not imply the specified permission, the method will not
   be executed.
 * `@griffon.plugins.shiro.annotation.RequiresRoles` - Requires the currently
   executing Subject to have all of the specified roles. If they do not have the
   role(s), the method will not be executed.

The annotations may be applied at the class level, in which case all actions will
inherit those constraints. Annotations applied to methods/closures override those
applied at the class level, for example

    import griffon.plugins.shiro.annotation.*

    @RequiresAuthentication
    class PrinterController {
       @RequiresPermission('printer:print')
       def print = { ... }

       @RequiresRoles('administrator')
       def configure = { ... }
    }

Anyone making use of `PrinterController` must be aun authenticated user. Everyone
with the permissions `printer:print` may call the `print` action. Only those users
that have been authenticated _and_ posses the `administrator` role are able to
call the `configure` action.

Apache Shiro's [Authentication Guide][2] presents the basic vocabulary and
behavior required to authenticate a user into the system. In particular, the
`SecurityUtils` class is used to store the current `Subject`, however it does so
by binding the instance to a `ThreadLocal` local variable; this poses a problem
in a multi-threaded environment such as a Griffon application. In order to solve
this problem this plugin provides a holder class for the `Subject`, as there
should only one. The holder is `griffon.plugins.shiro.SubjectHolder`. It's highly
recommended you make use of this class instead of `SecurityUtils` to grab hold
of the `Subject`. Here's a trivial implementation of a login controller that
shows what we've learned so far

    import griffon.plugins.shiro.annotation.*
    import griffon.plugins.shiro.SubjectHolder
    import org.apache.shiro.authc.UsernamePasswordToken

    class LoginController {
        def model

        @RequiresGuest
        def login = {
            UsernamePasswordToken token = new UsernamePasswordToken(
                model.username, model.password)
            SubjectHolder.subject.login(token)
        }

        @RequiresAuthentication
        def logout = {
            SubjectHolder.subject.logout()
        }
    }

The `login` action will be executed when there's no authenticated user while
the `logout` action will be executed only if the user is currently authenticated.

Configuration
-------------

The plugin requires an instanceof `org.apache.shiro.mgt.SecurityManager` to work.
For this reason it expects a className to be configured using the following
configuration flag

     shiro.security.manager.factory

This class must implement `griffon.plugins.shiro.factory.SecurityManagerFactory`.
If no value is configured then the plugin will proceed by instantiating a default
factory that relies on a properties based [Realm][3], whose default settings point
to a file named `shiro-users.properties` that must be available in the classpath.
The location of this resource may be changed too, defining a different value for

    shiro.realm.resource.path

Security failures are handled by default by simply logging the failed attempt.
This behavior can be chanhed too, for example displaying a dialog with a meaningful
message. The configuration flag that controls this behavior is

    shiro.security.failure.handler

Its value should be a className implementing `griffon.plugins.shiro.SecurityFailureHandler`.

The following section was adapted from [grails-shiro][4] original by Peter Ledbrook.

### Fine-tuning the access control

The default Shiro setup provided this plugin  is very flexible and powerful. It's
based on permission strings known as "wildcard permissions" that are simple to
use, but in some ways difficult to understand because they are also very flexible.

#### About wildcard permissions

Let's start with an example. Say you want to protect access to your company's
printers such that some people can print to particular printers, while others
can find out what jobs are currently in the queue. The basic type of permission
is therefore "printer", while we have two sub-types: "query" and "print". We
also want to restrict access on a per-printer basis, so we then have a second
sub-type that is the printer name. In wildcard permission format, the permission
requirements are

    printer:query:lp720 0
    printer:print:epsoncolor

Notice how each part is separated by a colon? That's how the wildcard permission
format separates what it calls "parts". It's also worth pointing out at this
stage that Apache Shiro has no understanding of printer permissions - they are
used and interpreted by the application.

So those are permission requirements. They state what permission is required to
do something. In the above example, the first permission says that a user must
have the right to query the "lp7200" printer. That's just the application's
interpretation of the string, though. You still need to code the permission
requirement into your application. A simple way to do this is in a condition:

    if (SubjectHolder.subject.isPermitted("printer:query:lp7200")) {
        // Return the current jobs on printer lp7200
    }

On the other side of the coin, you have permission assignments where you say what
rights particular users have. In the quick start example, you saw a permission
assignment in the BootStrap class.

Assignments look a lot like permission requirements, but they also support syntax
for wildcards and specifying multiple types or sub-types. What do I mean by that?
Well, imagine you want a user to have print access to all the printers in a company.
You could assign all the permissions manually:

    printer:print:lp7200
    printer:print:epsoncolor
    ...

but this doesn't scale well, particularly when new printers are added. You can
instead use a wildcard:

    printer:print:*

This does scale, because it covers any new printers as well. You could even allow
access to all actions on all printers:

    printer:*:*

or all actions on a single printer:

    printer:*:lp7200

or even specific actions:

    printer:query,print:lp7200

The '*' wildcard and ',' sub-type separator can be used in any part of the
permission, even the first part as you saw in the BootStrap example.

One final thing to note about permission assignments: missing parts imply that
the user has access to all values corresponding to that part. In other words,

    printer:print

is equivalent to

    printer:print:*

and

    printer

is equivalent to

    printer:*:*

However, you can only leave off parts from the end of the string, so this:

    printer:lp7200

is not equivalent to

    printer:*:lp7200

Permission assignments like these are typically done at the database level,
although it depends on your realm implementation. With the default realm
installed by quick-start you can assign permissions directly to users or via roles.

[1]: http://shiro.apache.org/
[2]: http://shiro.apache.org/java-authentication-guide.html
[3]: http://shiro.apache.org/static/current/apidocs/org/apache/shiro/realm/Realm.html
[4]: http://grails.org/plugin/shiro
'''
}
