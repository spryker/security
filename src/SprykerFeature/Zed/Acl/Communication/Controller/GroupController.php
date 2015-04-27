<?php

namespace SprykerFeature\Zed\Acl\Communication\Controller;

use SprykerFeature\Zed\Acl\Communication\AclDependencyContainer;
use SprykerFeature\Zed\Application\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method AclDependencyContainer getDependencyContainer()
 */
class GroupController extends AbstractController
{
    const USER_LIST_URL = '/acl/users';

    /**
     * @param Request $request
     *
     * @return array
     */
    public function indexAction(Request $request)
    {
        $idGroup = $request->get('id');
        $query=sprintf("?id=%s", $idGroup);

        return $this->viewResponse(['query' => $query]);
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function formAction(Request $request)
    {
        $form = $this->getDependencyContainer()->createGroupForm(
            $request
        );

        $idGroup = $request->get('id');
        if (!empty($idGroup)) {
            $form->setGroupId($idGroup);
        }

        $statusCode = 200;

        $form->init();

        if ($form->isValid()) {
            if (!empty($idGroup)) {
                $data = $form->getRequestData();
                $group = $this->getLocator()->acl()->transferGroup();
                $group->setIdAclGroup($idGroup);
                $group->setName($data['name']);
                $this->getLocator()->acl()->facade()->updateGroup($group);
            } else {
                $statusCode = 400;
            }
        }

        return $this->jsonResponse($form->renderData(), $statusCode);
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function rulesAction(Request $request)
    {
        $idGroup = $request->get('id');
        $grid = $this->getDependencyContainer()->createRulesetGrid($request, $idGroup);

        $data = $grid->renderData();

        return $this->jsonResponse($data);
    }

    public function rolesAction(Request $request)
    {
        $idGroup = $request->get('id');
    }
}
