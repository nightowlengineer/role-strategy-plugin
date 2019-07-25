package org.jenkinsci.plugins.rolestrategy;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.michelin.cio.hudson.plugins.rolestrategy.Role;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;
import hudson.model.*;
import hudson.security.AuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import jenkins.model.Jenkins;
import jenkins.model.ProjectNamingStrategy;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.rolestrategy.casc.RoleBasedAuthorizationStrategyConfigurator;
import org.jenkinsci.plugins.rolestrategy.util.TemporaryUserSession;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.Issue;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;
import java.util.Set;

import static io.jenkins.plugins.casc.misc.Util.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.core.Is.is;
import static org.jenkinsci.plugins.rolestrategy.PermissionAssert.assertHasNoPermission;
import static org.jenkinsci.plugins.rolestrategy.PermissionAssert.assertHasPermission;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Oleg Nenashev
 * @since 2.11
 */
@RunWith(MockitoJUnitRunner.class)
public class RoleStrategyTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Before
    public void setup()
    {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    }

    @Test
    public void shouldReturnCustomConfigurator() {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        Configurator c = registry.lookup(RoleBasedAuthorizationStrategy.class);
        assertNotNull("Failed to find configurator for RoleBasedAuthorizationStrategy", c);
        assertEquals("Retrieved wrong configurator", RoleBasedAuthorizationStrategyConfigurator.class, c.getClass());
    }

    @Test
    @Issue("Issue #48")
    @ConfiguredWithCode("Configuration-as-Code.yml")
    public void shouldReadRolesCorrectly() throws Exception {
        User admin = User.getById("admin", false);
        User user1 = User.getById("user1", false);
        User user2 = User.getById("user2", true);
        assertNotNull(admin);
        assertNotNull(user1);
        Computer agent1 = j.jenkins.getComputer("agent1");
        Computer agent2 = j.jenkins.getComputer("agent2");
        Folder folderA = j.jenkins.createProject(Folder.class, "A");
        FreeStyleProject jobA1 = folderA.createProject(FreeStyleProject.class, "1");
        Folder folderB = j.jenkins.createProject(Folder.class, "B");
        FreeStyleProject jobB2 = folderB.createProject(FreeStyleProject.class, "2");

        AuthorizationStrategy s = j.jenkins.getAuthorizationStrategy();
        assertThat("Authorization Strategy has been read incorrectly",
            s, instanceOf(RoleBasedAuthorizationStrategy.class));
        RoleBasedAuthorizationStrategy rbas = (RoleBasedAuthorizationStrategy) s;

        Map<Role, Set<String>> globalRoles = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL);
        assertThat(globalRoles.size(), equalTo(2));

        // Admin has configuration access
        assertHasPermission(admin, j.jenkins, Jenkins.ADMINISTER, Jenkins.READ);
        assertHasPermission(user1, j.jenkins, Jenkins.READ);
        assertHasNoPermission(user1, j.jenkins, Jenkins.ADMINISTER, Jenkins.RUN_SCRIPTS);
        assertHasNoPermission(user2, j.jenkins, Jenkins.ADMINISTER, Jenkins.RUN_SCRIPTS);

        // Folder A is restricted to admin
        assertHasPermission(admin, folderA, Item.CONFIGURE);
        assertHasPermission(user1, folderA, Item.READ, Item.DISCOVER);
        assertHasNoPermission(user1, folderA, Item.CONFIGURE, Item.DELETE, Item.BUILD);

        // But they have access to jobs in Folder A
        assertHasPermission(admin, folderA, Item.CONFIGURE, Item.CANCEL);
        assertHasPermission(user1, jobA1, Item.READ, Item.DISCOVER, Item.CONFIGURE, Item.BUILD, Item.DELETE);
        assertHasPermission(user2, jobA1, Item.READ, Item.DISCOVER, Item.CONFIGURE, Item.BUILD, Item.DELETE);
        assertHasNoPermission(user1, folderA, Item.CANCEL);

        // FolderB is editable by user2, but he cannot delete it
        assertHasPermission(user2, folderB, Item.READ, Item.DISCOVER, Item.CONFIGURE, Item.BUILD);
        assertHasNoPermission(user2, folderB, Item.DELETE);
        assertHasNoPermission(user1, folderB, Item.CONFIGURE, Item.BUILD, Item.DELETE);

        // Only user1 can run on agent1, but he still cannot configure it
        assertHasPermission(admin, agent1, Computer.CONFIGURE, Computer.DELETE, Computer.BUILD);
        assertHasPermission(user1, agent1, Computer.BUILD);
        assertHasNoPermission(user1, agent1, Computer.CONFIGURE, Computer.DISCONNECT);

        // Same user still cannot build on agent2
        assertHasNoPermission(user1, agent2, Computer.BUILD);
    }

    @Test
    @ConfiguredWithCode("Configuration-as-Code.yml")
    public void shouldExportRolesCorrect() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("authorizationStrategy");

        String exported = toYamlString(yourAttribute);
        String expected = toStringFromYamlFile(this, "Configuration-as-Code-Export.yml");

        assertThat(exported, is(expected));
    }

    @Test
    @Issue("Issue #214")
    @ConfiguredWithCode("Configuration-as-Code2.yml")
    public void shouldHandleNullItemsAndAgentsCorrectly() throws Exception {
        AuthorizationStrategy s = j.jenkins.getAuthorizationStrategy();
        assertThat("Authorization Strategy has been read incorrectly",
            s, instanceOf(RoleBasedAuthorizationStrategy.class));
        RoleBasedAuthorizationStrategy rbas = (RoleBasedAuthorizationStrategy) s;

        Map<Role, Set<String>> globalRoles = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL);
        assertThat(globalRoles.size(), equalTo(2));
    }

    @Test
    @Issue("JENKINS-34337")
    @ConfiguredWithCode("Configuration-as-Code-With-Name-Strategy.yml")
    public void nameStrategyShouldHandleValidCreate() throws Exception {
        ProjectNamingStrategy s = j.jenkins.getProjectNamingStrategy();
        assertThat("Project Naming Strategy has been read incorrectly",
                s, instanceOf(RoleBasedProjectNamingStrategy.class));

        try(final TemporaryUserSession user = new TemporaryUserSession("user3")) {
            // Create a new job with the specified prefix (34337_.*)
            j.jenkins.createProject(FreeStyleProject.class, "34337_job");
        }
    }

    @Test(expected = Failure.class)
    @Issue("JENKINS-34337")
    @ConfiguredWithCode("Configuration-as-Code-With-Name-Strategy.yml")
    public void nameStrategyShouldFailWithInvalidCreate() throws Exception {
        ProjectNamingStrategy s = j.jenkins.getProjectNamingStrategy();
        assertThat("Authorization Strategy has been read incorrectly",
                s, instanceOf(RoleBasedProjectNamingStrategy.class));

        // Create a new job with the specified prefix (34337_.*)
        try(final TemporaryUserSession user = new TemporaryUserSession("user3")) {
            j.jenkins.createProject(FreeStyleProject.class, "invalid_name");
        }
        catch (Failure f)
        {
            if (!f.getMessage().contains("does not match the job name convention pattern"))
            {
                fail("Unexpected failure occurred when testing create: " + f.getMessage());
            }
            throw f;
        }

    }

    @Test
    @Issue("JENKINS-34337")
    @ConfiguredWithCode("Configuration-as-Code-With-Name-Strategy.yml")
    public void nameStrategyShouldAcceptValidRename() throws Exception {
        ProjectNamingStrategy s = j.jenkins.getProjectNamingStrategy();
        assertThat("Authorization Strategy has been read incorrectly",
                s, instanceOf(RoleBasedProjectNamingStrategy.class));

        try(final TemporaryUserSession user = new TemporaryUserSession("user3")) {
            FreeStyleProject job = j.jenkins.createProject(FreeStyleProject.class, "34337_job_to_rename_existing");
            StaplerRequest staplerRequest = mock(StaplerRequest.class);
            StaplerResponse staplerResponse = mock(StaplerResponse.class);
            when(staplerRequest.getParameter("name")).thenReturn("34337_job_to_rename_new");
            when(staplerRequest.getSubmittedForm()).thenReturn(new JSONObject());
            job.doConfigSubmit(staplerRequest, staplerResponse);
        }
    }

    @Test(expected = Failure.class)
    @Issue("JENKINS-34337")
    @ConfiguredWithCode("Configuration-as-Code-With-Name-Strategy.yml")
    public void nameStrategyShouldFailInvalidRename() throws Exception {
        ProjectNamingStrategy s = j.jenkins.getProjectNamingStrategy();
        assertThat("Authorization Strategy has been read incorrectly",
                s, instanceOf(RoleBasedProjectNamingStrategy.class));

        try(final TemporaryUserSession user = new TemporaryUserSession("user3")) {
            // Create a new job with the specified prefix (34337_.*)
            FreeStyleProject job = j.jenkins.createProject(FreeStyleProject.class, "34337_job_to_rename_existing");
            StaplerRequest staplerRequest = mock(StaplerRequest.class);
            StaplerResponse staplerResponse = mock(StaplerResponse .class);
            when(staplerRequest.getParameter("name")).thenReturn("invalid_name");
            when(staplerRequest.getSubmittedForm()).thenReturn(new JSONObject());
            job.doConfigSubmit(staplerRequest, staplerResponse);
        }
        catch (Failure f)
        {
            if (!f.getMessage().contains("does not match the job name convention pattern"))
            {
                fail("Unexpected failure occurred when testing rename: " + f.getMessage());
            }
            throw f;
        }
    }
}
