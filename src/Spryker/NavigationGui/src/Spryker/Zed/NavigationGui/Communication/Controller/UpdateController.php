<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\NavigationGui\Communication\Controller;

use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\NavigationGui\Communication\NavigationGuiCommunicationFactory getFactory()
 */
class UpdateController extends AbstractController
{

    const PARAM_ID_NAVIGATION = 'id-navigation';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $idNavigation = $this->castId($request->query->getInt(self::PARAM_ID_NAVIGATION));
        $navigationFormDataProvider = $this->getFactory()->createNavigationFormDataProvider();
        $navigationForm = $this->getFactory()
            ->createUpdateNavigationForm(
                $navigationFormDataProvider->getData($idNavigation),
                $navigationFormDataProvider->getOptions()
            )
            ->handleRequest($request);

        if ($navigationForm->isValid()) {
            $navigationTransfer = $navigationForm->getData();
            $this->getFactory()
                ->getNavigationFacade()
                ->updateNavigation($navigationTransfer);

            $this->addSuccessMessage(sprintf('Navigation element %d was updated successfully.', $idNavigation));

            return $this->redirectResponse('/navigation-gui');
        }

        return $this->viewResponse([
            'navigationForm' => $navigationForm->createView(),
            'idNavigation' => $idNavigation,
        ]);
    }

}
