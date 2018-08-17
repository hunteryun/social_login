<?php

namespace Hunter\social_login\Controller;

use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Response\JsonResponse;
use Overtrue\Socialite\SocialiteManager;

/**
 * Class social_login.
 *
 * @package Hunter\social_login\Controller
 */
class SocialLoginController {

  /**
   * @var SocialiteManager
   */
  protected $socialite;

  /**
   * config constructor.
   */
  public function __construct() {
    $config = [
        'facebook' => [
            'client_id'     => variable_get('facebook_client_id'),
            'client_secret' => variable_get('facebook_client_secret'),
            'redirect'      => variable_get('facebook_callback'),
        ],
        'google' => [
            'client_id'     => variable_get('google_client_id'),
            'client_secret' => variable_get('google_client_secret'),
            'redirect'      => variable_get('google_callback'),
        ],
        'github' => [
            'client_id'     => variable_get('github_client_id'),
            'client_secret' => variable_get('github_client_secret'),
            'redirect'      => variable_get('github_callback'),
        ],
    ];

    $this->socialite = new SocialiteManager($config);
  }

  /**
   * facebook login page.
   *
   * @return string
   *   Return facebook login page string.
   */
  public function facebook_login(ServerRequest $request) {
    $response = $this->socialite->driver('facebook')->redirect();
    return $response->send();
  }

  /**
   * facebook callback page.
   *
   * @return string
   *   Return facebook callback page string.
   */
  public function facebook_callback(ServerRequest $request) {
    $user = $this->socialite->driver('facebook')->user();
    session()->set('socialite_user', $user);

    if(is_object($user)){
      $this->user_createorlogin($user);
      return redirect('/account/dashboard');
    }else{
      hunter_set_message('Authorized login failed！', 'error');
      return redirect('/login');
    }
  }

  /**
   * google login page.
   *
   * @return string
   *   Return google login page string.
   */
  public function google_login(ServerRequest $request) {
    $scopes = [
      'profile',
      'https://www.googleapis.com/auth/contacts.readonly'
    ];
    $response = $this->socialite->driver('google')->scopes($scopes)->redirect();
    return $response->send();
  }

  /**
   * google callback page.
   *
   * @return string
   *   Return google callback page string.
   */
  public function google_callback(ServerRequest $request) {
    $scopes = [
      'profile',
      'https://www.googleapis.com/auth/contacts.readonly'
    ];

    $user = $this->socialite->driver('google')->scopes($scopes)->user();
    session()->set('socialite_user', $user);

    if(is_object($user)){
      $this->user_createorlogin($user);
      return redirect('/account/dashboard');
    }else{
      hunter_set_message('Authorized login failed！', 'error');
      return redirect('/login');
    }
  }

  /**
   * github login page.
   *
   * @return string
   *   Return github login page string.
   */
  public function github_login(ServerRequest $request) {
    $response = $this->socialite->driver('github')->redirect();
    return $response->send();
  }

  /**
   * github callback page.
   *
   * @return string
   *   Return github callback page string.
   */
  public function github_callback(ServerRequest $request) {
    $user = $this->socialite->driver('github')->user();
    session()->set('socialite_user', $user);

    if(is_object($user)){
      $this->user_createorlogin($user);
      return redirect('/account/dashboard');
    }else{
      hunter_set_message('Authorized login failed！', 'error');
      return redirect('/login');
    }
  }

  /**
   * Social create user after login.
   */
  public function user_createorlogin($user) {
    $existed_user = db_select('user', 'u')
              ->fields('u')
              ->condition('email', $user->getEmail())
              ->execute()
              ->fetchObject();

    if($existed_user){
      db_update('user')
        ->fields(array(
          'accessed' => time(),
        ))
        ->condition('uid', $existed_user->uid)
        ->execute();
      session()->set('ecommerce_user', $existed_user);
    }else{
      $uid = db_insert('user')
        ->fields(array(
          'username' => $user->getName() ? $user->getName() : $user->getEmail(),
          'password' => hunter_password_hash('password'),
          'nickname' => $user->getNickname() ? $user->getNickname() : $user->getName(),
          'email' => $user->getEmail(),
          'provider' => $user->getProviderName(),
          'avatar' => $user->getAvatar() ? $user->getAvatar() : '/theme/hunter/assets/avatar/'.rand(0,38).'.jpg',
          'status' => 1,
          'created' => time(),
          'updated' => time(),
          'accessed' => time()
        ))
        ->execute();

      $new_user = db_select('user', 'u')
                ->fields('u')
                ->condition('uid', $uid)
                ->execute()
                ->fetchObject();

      session()->set('ecommerce_user', $new_user);
    }
  }

}
