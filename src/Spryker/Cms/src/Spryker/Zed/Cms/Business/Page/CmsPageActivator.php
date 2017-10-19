<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cms\Business\Page;

use Exception;
use Spryker\Shared\Cms\CmsConstants;
use Spryker\Zed\Cms\Business\Exception\CannotActivatePageException;
use Spryker\Zed\Cms\Business\Exception\MissingPageException;
use Spryker\Zed\Cms\Dependency\Facade\CmsToTouchInterface;
use Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface;
use Throwable;

class CmsPageActivator implements CmsPageActivatorInterface
{
    /**
     * @var \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface
     */
    protected $cmsQueryContainer;

    /**
     * @var \Spryker\Zed\Cms\Dependency\Facade\CmsToTouchInterface
     */
    protected $touchFacade;

    /**
     * @param \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface $cmsQueryContainer
     * @param \Spryker\Zed\Cms\Dependency\Facade\CmsToTouchInterface $touchFacade
     */
    public function __construct(CmsQueryContainerInterface $cmsQueryContainer, CmsToTouchInterface $touchFacade)
    {
        $this->cmsQueryContainer = $cmsQueryContainer;
        $this->touchFacade = $touchFacade;
    }

    /**
     * @param int $idCmsPage
     *
     * @throws \Exception
     * @throws \Throwable
     *
     * @return void
     */
    public function activate($idCmsPage)
    {
        $cmsPageEntity = $this->getCmsPageEntity($idCmsPage);

        $this->assertCanActivatePage($idCmsPage);

        try {
            $this->cmsQueryContainer->getConnection()->beginTransaction();

            $cmsPageEntity->setIsActive(true);
            $cmsPageEntity->save();

            $this->touchFacade->touchActive(CmsConstants::RESOURCE_TYPE_PAGE, $cmsPageEntity->getIdCmsPage());

            $this->cmsQueryContainer->getConnection()->commit();
        } catch (Exception $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        } catch (Throwable $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        }
    }

    /**
     * @param int $idCmsPage
     *
     * @throws \Spryker\Zed\Cms\Business\Exception\CannotActivatePageException
     *
     * @return bool
     */
    protected function assertCanActivatePage($idCmsPage)
    {
        if ($this->countNumberOfGlossaryKeysForIdCmsPage($idCmsPage) === 0) {
            throw new CannotActivatePageException(
                sprintf('Cannot activate CMS page, page placeholders not provided!')
            );
        }

         return true;
    }

    /**
     * @param int $idCmsPage
     *
     * @throws \Exception
     * @throws \Throwable
     *
     * @return void
     */
    public function deactivate($idCmsPage)
    {
        $cmsPageEntity = $this->getCmsPageEntity($idCmsPage);

        try {
            $this->cmsQueryContainer->getConnection()->beginTransaction();

            $cmsPageEntity->setIsActive(false);
            $cmsPageEntity->save();

            $this->touchFacade->touchActive(CmsConstants::RESOURCE_TYPE_PAGE, $cmsPageEntity->getIdCmsPage());

            $this->cmsQueryContainer->getConnection()->commit();
        } catch (Exception $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        } catch (Throwable $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        }
    }

    /**
     * @param int $idCmsPage
     *
     * @throws \Spryker\Zed\Cms\Business\Exception\MissingPageException
     *
     * @return \Orm\Zed\Cms\Persistence\SpyCmsPage
     */
    protected function getCmsPageEntity($idCmsPage)
    {
        $cmsPageEntity = $this->cmsQueryContainer
            ->queryPageById($idCmsPage)
            ->findOne();

        if ($cmsPageEntity === null) {
            throw new MissingPageException(
                sprintf(
                    'CMS page with id "%d" not found.',
                    $idCmsPage
                )
            );
        }
        return $cmsPageEntity;
    }

    /**
     * @param int $idCmsPage
     *
     * @return int
     */
    protected function countNumberOfGlossaryKeysForIdCmsPage($idCmsPage)
    {
        return $this->cmsQueryContainer->queryGlossaryKeyMappingsByPageId($idCmsPage)->count();
    }
}
