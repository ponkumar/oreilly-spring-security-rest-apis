package io.jzheaux.springsecurity.goals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserRepositoryUserDetailsService implements UserDetailsService {

  private final UserRepository users;

  public UserRepositoryUserDetailsService(UserRepository users) {
    this.users = users;
  }

  @Override
  public UserDetails loadUserByUsername(String usernname) throws UsernameNotFoundException {
    return this.users.findByUsername(usernname).map(UserBridge::new).orElseThrow(() -> new UsernameNotFoundException("USer Not Found"));
  }

  private static class UserBridge extends User implements UserDetails {
    private final Collection<GrantedAuthority> authorities;

    public UserBridge(User user){
      super(user);
      this.authorities=user.getUserAuthorities().stream().map(
          userAuthority -> new SimpleGrantedAuthority(userAuthority.getAuthority())).collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
      return true;
    }

    @Override
    public boolean isAccountNonLocked() {
      return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
      return true;
    }
  }
}
