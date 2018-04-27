
/**   
* 文件名：UserController.java   
*     
* Copyright ©2018 重庆若谷信息技术有限公司 版权所有.   
*   
*/

package authserver;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zjx
 * @date 2018年4月26日
 * @since 1.0.0
 */
@RestController
public class UserController {

	@RequestMapping("/user")
	public Principal user(Principal user) {
		return user;
	}
}
